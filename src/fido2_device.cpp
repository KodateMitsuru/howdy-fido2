#include "fido2_device.h"

#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstring>
#include <thread>

#include "cbor_helper.h"

namespace howdy {

// CTAPHID 常量
constexpr uint32_t CTAPHID_BROADCAST_CID = 0xFFFFFFFF;
constexpr uint8_t CTAPHID_INIT_PACKET_FLAG = 0x80;

// 能力标志
constexpr uint8_t CAPABILITY_WINK = 0x01;
constexpr uint8_t CAPABILITY_CBOR = 0x04;
constexpr uint8_t CAPABILITY_NMSG = 0x08;

// CTAP2 命令码
constexpr uint8_t CTAP2_CMD_MAKE_CREDENTIAL = 0x01;
constexpr uint8_t CTAP2_CMD_GET_ASSERTION = 0x02;
constexpr uint8_t CTAP2_CMD_GET_INFO = 0x04;
constexpr uint8_t CTAP2_CMD_CLIENT_PIN = 0x06;
constexpr uint8_t CTAP2_CMD_RESET = 0x07;

// CTAP2 状态码
constexpr uint8_t CTAP2_OK = 0x00;
constexpr uint8_t CTAP1_ERR_INVALID_COMMAND = 0x01;
constexpr uint8_t CTAP2_ERR_INVALID_CBOR = 0x12;
constexpr uint8_t CTAP2_ERR_OPERATION_DENIED = 0x27;
constexpr uint8_t CTAP2_ERR_UNHANDLED_REQUEST = 0x2D;
constexpr uint8_t CTAP2_ERR_NO_CREDENTIALS = 0x2E;
constexpr uint8_t CTAP2_ERR_NOT_ALLOWED = 0x30;

FIDO2Device::FIDO2Device() : rng_(std::random_device{}()) {
  // 生成 Attestation 密钥对
  if (!attestation_key_.generate()) {
    spdlog::warn("无法生成 Attestation 密钥");
  } else {
    // 生成自签名证书
    attestation_cert_ = CryptoUtils::generate_self_signed_cert(
        attestation_key_, "HowdyFIDO2", 3650);
    spdlog::info("Attestation 证书已生成 ({} 字节)", attestation_cert_.size());
  }

  // 初始化 TPM 存储并加载凭据
  if (tpm_storage_.initialize()) {
    load_credentials_from_tpm();
  } else {
    spdlog::warn("TPM 存储不可用: {}", tpm_storage_.last_error());
  }
}

FIDO2Device::~FIDO2Device() { stop(); }

bool FIDO2Device::start() {
  // 设置输出处理回调
  uhid_.set_output_handler([this](const std::vector<uint8_t>& data) {
    handle_ctaphid_message(data);
  });

  return uhid_.create();
}

void FIDO2Device::stop() { uhid_.destroy(); }

void FIDO2Device::handle_ctaphid_message(const std::vector<uint8_t>& data) {
  // 调试：打印原始数据
  spdlog::debug(
      "CTAPHID: 收到 {} 字节: {:02X}", data.size(),
      spdlog::to_hex(data.begin(),
                     data.begin() + std::min(data.size(), size_t(16))));

  if (data.size() < 5) {
    spdlog::error("CTAPHID: 数据包太短");
    return;
  }

  // Report ID 检测
  size_t offset = 0;
  if (data.size() == 65 && data[0] == 0x00) {
    offset = 1;
  }

  // 解析 Channel ID
  uint32_t channel_id = (static_cast<uint32_t>(data[offset + 0]) << 24) |
                        (static_cast<uint32_t>(data[offset + 1]) << 16) |
                        (static_cast<uint32_t>(data[offset + 2]) << 8) |
                        static_cast<uint32_t>(data[offset + 3]);

  uint8_t cmd_byte = data[offset + 4];

  // 检查是否为续传包 (高位为0)
  if (!(cmd_byte & CTAPHID_INIT_PACKET_FLAG)) {
    // 续传包处理
    uint8_t seq = cmd_byte;

    auto it = pending_messages_.find(channel_id);
    if (it == pending_messages_.end()) {
      spdlog::debug("CTAPHID: 续传包无对应初始包，忽略");
      return;
    }

    auto& pending = it->second;
    if (seq != pending.expected_seq) {
      spdlog::warn("CTAPHID: 续传包序号错误，期望 {} 收到 {}",
                   pending.expected_seq, seq);
      pending_messages_.erase(it);
      send_error(channel_id, CTAPHIDError::INVALID_SEQ);
      return;
    }

    // 复制续传包数据 (从 offset+5 开始，最多 59 字节)
    size_t copy_start = offset + 5;
    size_t remaining = pending.total_len - pending.data.size();
    size_t copy_len = std::min(remaining, data.size() - copy_start);

    for (size_t i = 0; i < copy_len && copy_start + i < data.size(); ++i) {
      pending.data.push_back(data[copy_start + i]);
    }

    pending.expected_seq++;

    spdlog::debug("CTAPHID: 续传包 seq={} 已收集 {}/{} 字节", seq,
                  pending.data.size(), pending.total_len);

    // 检查是否完成
    if (pending.data.size() >= pending.total_len) {
      std::vector<uint8_t> complete_data = std::move(pending.data);
      uint8_t cmd = pending.cmd;
      pending_messages_.erase(it);
      process_complete_message(channel_id, cmd, complete_data);
    }
    return;
  }

  // 初始化包处理
  auto cmd = static_cast<CTAPHIDCommand>(cmd_byte & 0x7F);
  uint16_t payload_len =
      (static_cast<uint16_t>(data[offset + 5]) << 8) | data[offset + 6];

  // 复制初始化包数据
  std::vector<uint8_t> payload;
  size_t init_data_start = offset + 7;
  size_t init_data_max = 57;  // 64 - 7 header bytes
  size_t copy_len =
      std::min(static_cast<size_t>(payload_len),
               std::min(init_data_max, data.size() - init_data_start));

  if (copy_len > 0 && init_data_start < data.size()) {
    payload.assign(data.begin() + init_data_start,
                   data.begin() + init_data_start + copy_len);
  }

  spdlog::debug("CTAPHID: CID={:#010X} CMD={:#04X} LEN={} (收到 {} 字节)",
                channel_id, static_cast<int>(cmd), payload_len, payload.size());

  // 如果需要更多数据，保存待处理消息
  if (payload_len > payload.size()) {
    PendingMessage pending;
    pending.channel_id = channel_id;
    pending.cmd = static_cast<uint8_t>(cmd);
    pending.total_len = payload_len;
    pending.data = std::move(payload);
    pending.expected_seq = 0;
    pending_messages_[channel_id] = std::move(pending);
    spdlog::debug("CTAPHID: 等待续传包...");
    return;
  }

  // 消息完整，直接处理
  process_complete_message(channel_id, static_cast<uint8_t>(cmd), payload);
}

void FIDO2Device::process_complete_message(uint32_t channel_id, uint8_t cmd,
                                           const std::vector<uint8_t>& data) {
  spdlog::debug("CTAPHID: 处理完整消息 CMD={:#04X} 数据={} 字节", cmd,
                data.size());

  switch (static_cast<CTAPHIDCommand>(cmd)) {
    case CTAPHIDCommand::INIT:
      if (data.size() >= 8) {
        handle_init(channel_id, data.data());
      } else {
        send_error(channel_id, CTAPHIDError::INVALID_LEN);
      }
      break;

    case CTAPHIDCommand::PING:
      handle_ping(channel_id, data);
      break;

    case CTAPHIDCommand::CBOR:
      handle_cbor(channel_id, data);
      break;

    case CTAPHIDCommand::MSG:
      handle_msg(channel_id, data);
      break;

    case CTAPHIDCommand::WINK:
      handle_wink(channel_id);
      break;

    case CTAPHIDCommand::CANCEL:
      spdlog::debug("CTAPHID: 取消命令");
      pending_messages_.erase(channel_id);
      break;

    default:
      spdlog::warn("CTAPHID: 未知命令 {:#04X}", cmd);
      send_error(channel_id, CTAPHIDError::INVALID_CMD);
      break;
  }
}

void FIDO2Device::handle_init(uint32_t channel_id, const uint8_t* nonce) {
  spdlog::debug("CTAPHID: 处理 INIT 命令");

  CTAPHIDInitResponse resp{};

  // 复制 nonce
  memcpy(resp.nonce, nonce, 8);

  // 分配或返回通道ID
  if (channel_id == CTAPHID_BROADCAST_CID) {
    resp.channel_id = allocate_channel_id();
  } else {
    resp.channel_id = channel_id;
  }

  // 设备信息
  resp.protocol_version = 2;  // CTAPHID protocol version
  resp.device_major = 1;
  resp.device_minor = 0;
  resp.device_build = 0;
  resp.capabilities = CAPABILITY_WINK | CAPABILITY_CBOR;

  // 注册通道
  {
    std::lock_guard<std::mutex> lock(channels_mutex_);
    active_channels_[resp.channel_id] = true;
  }

  // 构造响应数据
  std::vector<uint8_t> response_data(17);
  memcpy(response_data.data(), resp.nonce, 8);
  response_data[8] = (resp.channel_id >> 24) & 0xFF;
  response_data[9] = (resp.channel_id >> 16) & 0xFF;
  response_data[10] = (resp.channel_id >> 8) & 0xFF;
  response_data[11] = resp.channel_id & 0xFF;
  response_data[12] = resp.protocol_version;
  response_data[13] = resp.device_major;
  response_data[14] = resp.device_minor;
  response_data[15] = resp.device_build;
  response_data[16] = resp.capabilities;

  send_response(CTAPHID_BROADCAST_CID, CTAPHIDCommand::INIT, response_data);

  spdlog::debug("CTAPHID: 分配通道 ID: {:#010X}", resp.channel_id);
}

void FIDO2Device::handle_ping(uint32_t channel_id,
                              const std::vector<uint8_t>& data) {
  spdlog::debug("CTAPHID: 处理 PING 命令");
  // PING 响应原样返回数据
  send_response(channel_id, CTAPHIDCommand::PING, data);
}

void FIDO2Device::handle_cbor(uint32_t channel_id,
                              const std::vector<uint8_t>& data) {
  spdlog::debug("CTAPHID: 处理 CBOR 命令");

  if (data.empty()) {
    send_error(channel_id, CTAPHIDError::INVALID_LEN);
    return;
  }

  uint8_t ctap_cmd = data[0];
  std::vector<uint8_t> cbor_data(data.begin() + 1, data.end());

  spdlog::debug("CTAP2: 命令码 {:#04X}", ctap_cmd);

  std::vector<uint8_t> response;

  switch (ctap_cmd) {
    case CTAP2_CMD_GET_INFO:
      response = handle_get_info();
      break;

    case CTAP2_CMD_MAKE_CREDENTIAL:
      response = handle_make_credential(cbor_data);
      break;

    case CTAP2_CMD_GET_ASSERTION:
      response = handle_get_assertion(cbor_data);
      break;

    case CTAP2_CMD_CLIENT_PIN:
      spdlog::debug("CTAP2: CLIENT_PIN (返回无PIN)");
      response = {CTAP2_ERR_NOT_ALLOWED};
      break;

    case CTAP2_CMD_RESET:
      spdlog::debug("CTAP2: RESET");
      response = {CTAP2_OK};
      break;

    default:
      spdlog::warn("CTAP2: 不支持的命令");
      response = {CTAP1_ERR_INVALID_COMMAND};
      break;
  }

  send_response(channel_id, CTAPHIDCommand::CBOR, response);
}

std::vector<uint8_t> FIDO2Device::handle_get_info() {
  spdlog::debug("CTAP2: 处理 authenticatorGetInfo (使用 libcbor)");

  // 使用 CborEncoder 构建正确的 GetInfo 响应
  std::vector<std::string> versions = {"FIDO_2_0", "FIDO_2_1_PRE", "U2F_V2"};
  std::vector<std::string> extensions = {"credProtect", "hmac-secret"};

  // AAGUID (16 bytes)
  std::vector<uint8_t> aaguid = {'H', 'O', 'W', 'D', 'Y', 'F', 'I', 'D',
                                 'O', '2', 'D', 'E', 'V', 'I', 'C', 'E'};

  // Options - 按字母序排列 (libcbor 会自动处理)
  std::map<std::string, bool> options = {
      {"clientPin", false}, {"credMgmt", true}, {"plat", false},
      {"rk", true},         {"up", true},       {"uv", true}};

  uint32_t max_msg_size = 2048;
  std::vector<int> pin_protocols = {2, 1};

  std::vector<uint8_t> cbor_data =
      CborEncoder::encode_get_info(versions, extensions, aaguid, options,
                                   max_msg_size, pin_protocols, 8, 128);

  if (cbor_data.empty()) {
    spdlog::error("CTAP2: GetInfo CBOR 编码失败");
    return {CTAP2_ERR_UNHANDLED_REQUEST};
  }

  // 添加状态码
  std::vector<uint8_t> response;
  response.push_back(CTAP2_OK);
  response.insert(response.end(), cbor_data.begin(), cbor_data.end());

  spdlog::debug("CTAP2: 返回设备信息 ({} 字节)", response.size());

  // 打印响应的十六进制
  spdlog::debug(
      "CTAP2: GetInfo响应: {:02x}",
      spdlog::to_hex(response.begin(),
                     response.begin() + std::min(response.size(), size_t(32))));

  return response;
}

void FIDO2Device::handle_msg(uint32_t channel_id,
                             const std::vector<uint8_t>& data) {
  spdlog::debug("CTAPHID: 处理 U2F MSG 命令 ({} 字节)", data.size());

  // U2F APDU 格式: CLA INS P1 P2 [Lc Data] [Le]
  if (data.size() < 4) {
    std::vector<uint8_t> response = {0x6A, 0x80};  // SW_WRONG_LENGTH
    send_response(channel_id, CTAPHIDCommand::MSG, response);
    return;
  }

  uint8_t cla = data[0];
  uint8_t ins = data[1];
  uint8_t p1 = data[2];
  uint8_t p2 = data[3];

  spdlog::debug("U2F: CLA={:#04X} INS={:#04X} P1={:#04X} P2={:#04X}", cla, ins,
                p1, p2);

  std::vector<uint8_t> response;

  if (ins == 0x01) {
    // U2F_REGISTER
    spdlog::debug("U2F: REGISTER 请求 (P1={})", p1);

    // U2F 规范中，P1 通常为 0，但 Chrome/WebAuthn 可能使用 0x03 作为轮询
    // 无论 P1 值如何，我们都需要验证用户并返回注册响应
    if (verify_user("U2F 注册")) {
      // 用户验证成功，生成真正的注册响应
      response = generate_u2f_register_response(data);
    } else {
      // 验证失败或用户取消
      response = {0x69, 0x85};  // SW_CONDITIONS_NOT_SATISFIED
    }
  } else if (ins == 0x02) {
    // U2F_AUTHENTICATE
    spdlog::debug("U2F: AUTHENTICATE 请求");

    // P1=0x07 表示 "check-only"
    if (p1 == 0x07) {
      // check-only: 检查是否有这个凭据
      response = {0x69, 0x85};  // SW_CONDITIONS_NOT_SATISFIED = 需要触摸
    } else if (p1 == 0x03 || p1 == 0x08) {
      // enforce-user-presence-and-sign 或 dont-enforce
      if (p1 == 0x08 || verify_user("U2F 验证")) {
        response = generate_u2f_auth_response(data);
      } else {
        response = {0x6A, 0x80};
      }
    } else {
      response = {0x6A, 0x80};
    }
  } else if (ins == 0x03) {
    // U2F_VERSION
    spdlog::debug("U2F: VERSION 请求");
    response = {'U', '2', 'F', '_', 'V', '2', 0x90, 0x00};
  } else {
    spdlog::warn("U2F: 未知命令");
    response = {0x6D, 0x00};  // SW_INS_NOT_SUPPORTED
  }

  send_response(channel_id, CTAPHIDCommand::MSG, response);
}

bool FIDO2Device::verify_user(const std::string& operation) {
  // 检查是否有有效的验证缓存
  {
    std::lock_guard<std::mutex> lock(verification_mutex_);
    if (user_verified_) {
      auto now = std::chrono::steady_clock::now();
      auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                         now - verification_time_)
                         .count();
      if (elapsed < VERIFICATION_TIMEOUT_SECONDS) {
        spdlog::info("✅ 使用缓存的验证结果 (剩余 {} 秒)",
                     VERIFICATION_TIMEOUT_SECONDS - elapsed);
        // 添加小延迟，避免响应太快导致 Chrome 无法正确处理
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return true;
      }
      // 缓存过期
      user_verified_ = false;
    }

    // 检查是否已有验证在进行中
    if (verification_in_progress_) {
      spdlog::info("⏳ 验证进行中，请稍候...");
      return false;  // 返回 SW_CONDITIONS_NOT_SATISFIED，让 Chrome 继续轮询
    }

    verification_in_progress_ = true;
  }

  spdlog::info("");
  spdlog::info("========================================");
  spdlog::info("🔐 FIDO2 验证请求: {}", operation);
  spdlog::info("========================================");

  bool result = false;

  if (!use_pam_) {
    spdlog::info("PAM 验证已禁用，使用默认结果: {}",
                 default_auth_result_ ? "允许" : "拒绝");
    result = default_auth_result_;
  } else {
    spdlog::info("🔍 启动 PAM 验证 (服务: {})...", pam_service_);

    PAMAuthenticator pam(pam_service_);
    pam.set_timeout(30);
    pam.set_prompt_callback(
        [](const std::string& msg) { spdlog::info("   📢 {}", msg); });

    PAMResult pam_result = pam.authenticate();

    spdlog::info("========================================");

    switch (pam_result) {
      case PAMResult::SUCCESS:
        spdlog::info("✅ PAM 验证成功!");
        result = true;
        break;
      case PAMResult::AUTH_FAILED:
        spdlog::warn("❌ PAM 验证失败: {}", pam.last_error());
        result = false;
        break;
      case PAMResult::USER_CANCELLED:
        spdlog::info("⏹️  用户取消或超时");
        result = false;
        break;
      case PAMResult::ERROR:
      default:
        spdlog::error("⚠️  PAM 错误: {}", pam.last_error());
        spdlog::info("   回退到默认结果: {}",
                     default_auth_result_ ? "允许" : "拒绝");
        result = default_auth_result_;
        break;
    }
  }

  // 更新验证状态
  {
    std::lock_guard<std::mutex> lock(verification_mutex_);
    verification_in_progress_ = false;
    if (result) {
      user_verified_ = true;
      verification_time_ = std::chrono::steady_clock::now();
      spdlog::info("📝 验证结果已缓存 ({} 秒有效)",
                   VERIFICATION_TIMEOUT_SECONDS);
    }
  }

  return result;
}

std::vector<uint8_t> FIDO2Device::handle_make_credential(
    const std::vector<uint8_t>& cbor_data) {
  spdlog::debug("CTAP2: 处理 authenticatorMakeCredential (使用 libcbor)");
  spdlog::debug("CTAP2: CBOR 数据 {} 字节", cbor_data.size());

  // 解析 CBOR 请求
  auto req = CborDecoder::parse_make_credential(cbor_data);
  if (!req.valid) {
    spdlog::error("CTAP2: 无法解析 MakeCredential 请求");
    return {CTAP2_ERR_INVALID_CBOR};
  }

  spdlog::debug("CTAP2: RP ID = {}", req.rp_id);
  spdlog::debug("CTAP2: User = {} ({})", req.user_name, req.user_display_name);

  // 使用 PAM 验证用户
  if (!verify_user("创建 FIDO2 凭证")) {
    spdlog::warn("CTAP2: ❌ 用户验证失败，拒绝创建凭证");
    return {CTAP2_ERR_OPERATION_DENIED};
  }

  spdlog::info("CTAP2: ✅ 用户验证通过，创建凭证");

  // 计算 RP ID hash
  std::vector<uint8_t> rp_id_bytes(req.rp_id.begin(), req.rp_id.end());
  std::vector<uint8_t> rp_id_hash = CryptoUtils::sha256(rp_id_bytes);

  // 生成新的用户密钥对
  ECKeyPair user_key;
  if (!user_key.generate()) {
    spdlog::error("CTAP2: 无法生成用户密钥对");
    return {CTAP2_ERR_UNHANDLED_REQUEST};
  }

  std::vector<uint8_t> public_key = user_key.get_public_key();
  std::vector<uint8_t> private_key = user_key.get_private_key();

  spdlog::debug("CTAP2: 生成用户密钥对，公钥 {} 字节", public_key.size());

  // 生成凭证 ID (包含加密的私钥信息)
  std::vector<uint8_t> credential_id = CryptoUtils::random_bytes(16);
  credential_id.insert(credential_id.end(), private_key.begin(),
                       private_key.end());

  // 保存凭据
  StoredCredential cred;
  cred.key_handle = credential_id;
  cred.private_key = private_key;
  cred.app_id = rp_id_hash;
  cred.user_id = req.user_id;
  cred.user_name = req.user_name;
  cred.rp_id = req.rp_id;
  cred.counter = 0;
  credentials_[credential_id] = cred;

  // 保存到 TPM
  save_credentials_to_tpm();

  spdlog::debug("CTAP2: 凭据已保存，credential_id {} 字节",
                credential_id.size());

  // 检查是否有扩展请求
  bool has_extensions = !req.extensions.empty();
  int cred_protect_level = 0;
  if (req.extensions.count("credProtect")) {
    cred_protect_level = req.extensions.at("credProtect");
    spdlog::debug("CTAP2: 收到 credProtect={}", cred_protect_level);
  }

  // 构建 authData
  std::vector<uint8_t> auth_data;

  // RP ID hash (32 bytes)
  auth_data.insert(auth_data.end(), rp_id_hash.begin(), rp_id_hash.end());

  // Flags: UP=1, UV=1, AT=1, ED=1(if extensions)
  // 0x45 = 01000101 (UP | UV | AT)
  // 0xC5 = 11000101 (UP | UV | AT | ED)
  uint8_t flags = has_extensions ? 0xC5 : 0x45;
  auth_data.push_back(flags);

  // Counter (4 bytes, big-endian)
  uint32_t counter = ++cred.counter;
  auth_data.push_back((counter >> 24) & 0xFF);
  auth_data.push_back((counter >> 16) & 0xFF);
  auth_data.push_back((counter >> 8) & 0xFF);
  auth_data.push_back(counter & 0xFF);

  // AAGUID (16 bytes)
  const char* aaguid = "HOWDYFIDO2DEVICE";
  for (int i = 0; i < 16; ++i) auth_data.push_back(aaguid[i]);

  // Credential ID length (2 bytes, big-endian)
  uint16_t cred_id_len = static_cast<uint16_t>(credential_id.size());
  auth_data.push_back((cred_id_len >> 8) & 0xFF);
  auth_data.push_back(cred_id_len & 0xFF);

  // Credential ID
  auth_data.insert(auth_data.end(), credential_id.begin(), credential_id.end());

  // Credential Public Key (COSE_Key format) - 使用 libcbor 编码
  std::vector<uint8_t> cose_key = CborEncoder::encode_cose_key(public_key);
  if (cose_key.empty()) {
    spdlog::error("CTAP2: COSE Key 编码失败");
    return {CTAP2_ERR_UNHANDLED_REQUEST};
  }
  auth_data.insert(auth_data.end(), cose_key.begin(), cose_key.end());

  // Extensions (如果有)
  if (has_extensions) {
    // 构建扩展 CBOR map
    // {"credProtect": level}
    if (cred_protect_level > 0) {
      auth_data.push_back(0xA1);  // map(1)
      // "credProtect" (11 bytes)
      auth_data.push_back(0x6B);  // text(11)
      for (char c : std::string("credProtect")) auth_data.push_back(c);
      auth_data.push_back(cred_protect_level);  // 1-3
      spdlog::debug("CTAP2: 添加 credProtect 扩展: {}", cred_protect_level);
    }
  }

  spdlog::debug("CTAP2: authData {} 字节", auth_data.size());

  // 使用 "none" attestation (最兼容的方式)
  // 构建响应: {1: "none", 2: authData, 3: {}}
  std::vector<uint8_t> response;
  response.push_back(CTAP2_OK);

  response.push_back(0xA3);  // map(3)

  // 1: fmt = "none"
  response.push_back(0x01);
  response.push_back(0x64);  // text(4)
  response.push_back('n');
  response.push_back('o');
  response.push_back('n');
  response.push_back('e');

  // 2: authData
  response.push_back(0x02);
  if (auth_data.size() < 24) {
    response.push_back(0x40 | auth_data.size());
  } else if (auth_data.size() < 256) {
    response.push_back(0x58);
    response.push_back(static_cast<uint8_t>(auth_data.size()));
  } else {
    response.push_back(0x59);
    response.push_back((auth_data.size() >> 8) & 0xFF);
    response.push_back(auth_data.size() & 0xFF);
  }
  response.insert(response.end(), auth_data.begin(), auth_data.end());

  // 3: attStmt = {} (空 map)
  response.push_back(0x03);
  response.push_back(0xA0);  // map(0)

  spdlog::debug("CTAP2: MakeCredential 响应完成 ({} 字节)", response.size());
  return response;
}

std::vector<uint8_t> FIDO2Device::handle_get_assertion(
    const std::vector<uint8_t>& cbor_data) {
  spdlog::debug("CTAP2: 处理 authenticatorGetAssertion (使用 libcbor)");
  spdlog::debug("CTAP2: CBOR 数据 {} 字节", cbor_data.size());

  // 解析 CBOR 请求
  auto req = CborDecoder::parse_get_assertion(cbor_data);
  if (!req.valid) {
    spdlog::error("CTAP2: 无法解析 GetAssertion 请求");
    return {CTAP2_ERR_INVALID_CBOR};
  }

  spdlog::debug("CTAP2: RP ID = {}", req.rp_id);

  // 使用 PAM 验证用户
  if (!verify_user("FIDO2 身份验证")) {
    spdlog::warn("CTAP2: ❌ 用户验证失败");
    return {CTAP2_ERR_OPERATION_DENIED};
  }

  spdlog::info("CTAP2: ✅ 用户验证通过");

  // 计算 rp_id_hash
  std::vector<uint8_t> rp_id_bytes(req.rp_id.begin(), req.rp_id.end());
  std::vector<uint8_t> rp_id_hash = CryptoUtils::sha256(rp_id_bytes);

  // 查找匹配的凭据
  StoredCredential* found_cred = nullptr;
  std::vector<uint8_t> found_cred_id;

  // 先检查 allowList
  if (!req.allow_list.empty()) {
    for (const auto& allowed_id : req.allow_list) {
      auto it = credentials_.find(allowed_id);
      if (it != credentials_.end() && it->second.app_id == rp_id_hash) {
        found_cred = &it->second;
        found_cred_id = allowed_id;
        spdlog::debug("CTAP2: 在 allowList 中找到匹配凭据");
        break;
      }
    }
  }

  // 如果 allowList 没有匹配，搜索所有凭据 (resident key)
  if (!found_cred) {
    for (auto& [cred_id, cred] : credentials_) {
      if (cred.app_id == rp_id_hash) {
        found_cred = &cred;
        found_cred_id = cred_id;
        spdlog::debug("CTAP2: 找到 resident key 凭据");
        break;
      }
    }
  }

  if (!found_cred) {
    spdlog::warn("CTAP2: 未找到匹配凭据 (rp_id={})", req.rp_id);
    return {CTAP2_ERR_NO_CREDENTIALS};
  }

  // 重建用户密钥
  ECKeyPair user_key;
  if (!user_key.set_private_key(found_cred->private_key)) {
    spdlog::error("CTAP2: 无法恢复用户密钥");
    return {CTAP2_ERR_UNHANDLED_REQUEST};
  }

  // 增加计数器
  found_cred->counter++;
  uint32_t counter = found_cred->counter;

  // 保存到 TPM (计数器已更新)
  save_credentials_to_tpm();

  // 构建 authData
  std::vector<uint8_t> auth_data;

  // RP ID hash (32 bytes)
  auth_data.insert(auth_data.end(), rp_id_hash.begin(), rp_id_hash.end());

  // Flags: UP=1, UV=1 (0x05)
  auth_data.push_back(0x05);

  // Counter (4 bytes, big-endian)
  auth_data.push_back((counter >> 24) & 0xFF);
  auth_data.push_back((counter >> 16) & 0xFF);
  auth_data.push_back((counter >> 8) & 0xFF);
  auth_data.push_back(counter & 0xFF);

  spdlog::debug("CTAP2: authData {} 字节, counter={}", auth_data.size(),
                counter);

  // 签名数据 = authData || clientDataHash
  std::vector<uint8_t> sig_data;
  sig_data.insert(sig_data.end(), auth_data.begin(), auth_data.end());
  sig_data.insert(sig_data.end(), req.client_data_hash.begin(),
                  req.client_data_hash.end());

  spdlog::debug("CTAP2: 签名数据 {} 字节 (authData {} + clientDataHash {})",
                sig_data.size(), auth_data.size(), req.client_data_hash.size());

  // 打印 clientDataHash 的前几个字节用于调试
  spdlog::debug(
      "CTAP2: clientDataHash: {:02x}",
      spdlog::to_hex(req.client_data_hash.begin(),
                     req.client_data_hash.begin() +
                         std::min(size_t(8), req.client_data_hash.size())));

  std::vector<uint8_t> signature = user_key.sign(sig_data);
  if (signature.empty()) {
    spdlog::error("CTAP2: 签名失败");
    return {CTAP2_ERR_UNHANDLED_REQUEST};
  }

  spdlog::debug("CTAP2: 签名生成完成，{} 字节", signature.size());

  // 验证签名（调试用）
  if (user_key.verify(sig_data, signature)) {
    spdlog::debug("CTAP2: ✓ 签名自验证通过");
  } else {
    spdlog::error("CTAP2: ✗ 签名自验证失败！");
  }

  // 使用 libcbor 编码响应
  std::vector<uint8_t> cbor_response =
      CborEncoder::encode_get_assertion_response(found_cred_id, auth_data,
                                                 signature, found_cred->user_id,
                                                 found_cred->user_name);

  if (cbor_response.empty()) {
    spdlog::error("CTAP2: 响应编码失败");
    return {CTAP2_ERR_UNHANDLED_REQUEST};
  }

  // 添加状态码
  std::vector<uint8_t> response;
  response.push_back(CTAP2_OK);
  response.insert(response.end(), cbor_response.begin(), cbor_response.end());

  spdlog::debug("CTAP2: GetAssertion 响应完成 ({} 字节)", response.size());
  return response;
}

void FIDO2Device::handle_wink(uint32_t channel_id) {
  spdlog::info("CTAPHID: 处理 WINK 命令 ✨");
  spdlog::info("        💡 设备闪烁中...");

  // WINK 响应为空
  send_response(channel_id, CTAPHIDCommand::WINK, {});
}

void FIDO2Device::send_response(uint32_t channel_id, CTAPHIDCommand cmd,
                                const std::vector<uint8_t>& data) {
  spdlog::debug("CTAPHID: 发送响应 CID={:#010X} CMD={:#04X} ({} 字节)",
                channel_id, static_cast<int>(cmd), data.size());

  constexpr size_t INIT_DATA_SIZE = 57;  // 64 - 7
  constexpr size_t CONT_DATA_SIZE = 59;  // 64 - 5

  std::vector<uint8_t> packet(HID_REPORT_SIZE, 0);

  // Channel ID
  packet[0] = (channel_id >> 24) & 0xFF;
  packet[1] = (channel_id >> 16) & 0xFF;
  packet[2] = (channel_id >> 8) & 0xFF;
  packet[3] = channel_id & 0xFF;

  // Command
  packet[4] = static_cast<uint8_t>(cmd) | CTAPHID_INIT_PACKET_FLAG;

  // Total length
  uint16_t total_len = static_cast<uint16_t>(data.size());
  packet[5] = (total_len >> 8) & 0xFF;
  packet[6] = total_len & 0xFF;

  // Initial packet data
  size_t offset = 0;
  size_t copy_len = std::min(data.size(), INIT_DATA_SIZE);
  if (copy_len > 0) {
    memcpy(packet.data() + 7, data.data(), copy_len);
    offset = copy_len;
  }

  uhid_.send_input(packet);

  // Continuation packets
  uint8_t seq = 0;
  while (offset < data.size()) {
    std::fill(packet.begin(), packet.end(), 0);

    packet[0] = (channel_id >> 24) & 0xFF;
    packet[1] = (channel_id >> 16) & 0xFF;
    packet[2] = (channel_id >> 8) & 0xFF;
    packet[3] = channel_id & 0xFF;
    packet[4] = seq++;

    copy_len = std::min(data.size() - offset, CONT_DATA_SIZE);
    memcpy(packet.data() + 5, data.data() + offset, copy_len);
    offset += copy_len;

    uhid_.send_input(packet);
    spdlog::debug("CTAPHID: 续传包 seq={}", seq - 1);
  }
}

void FIDO2Device::send_error(uint32_t channel_id, CTAPHIDError error) {
  std::vector<uint8_t> error_data = {static_cast<uint8_t>(error)};
  send_response(channel_id, CTAPHIDCommand::ERROR, error_data);
}

std::vector<uint8_t> FIDO2Device::generate_u2f_register_response(
    const std::vector<uint8_t>& request) {
  spdlog::debug("U2F: 生成注册响应 (使用真实加密)");

  // U2F Register 请求格式:
  // Byte 0-31: challenge (32 bytes)
  // Byte 32-63: application (app_id hash, 32 bytes)

  if (request.size() < 7 + 64) {  // CLA INS P1 P2 Lc(3) + 64 bytes data
    spdlog::warn("U2F: 注册请求数据太短");
    return {0x6A, 0x80};  // SW_WRONG_LENGTH
  }

  // 解析扩展 APDU: CLA INS P1 P2 00 Lc1 Lc2 Data...
  size_t data_offset = 7;  // 跳过 CLA INS P1 P2 00 Lc1 Lc2
  if (request.size() < data_offset + 64) {
    spdlog::warn("U2F: 注册请求数据不完整");
    return {0x6A, 0x80};
  }

  std::vector<uint8_t> challenge(request.begin() + data_offset,
                                 request.begin() + data_offset + 32);
  std::vector<uint8_t> app_id(request.begin() + data_offset + 32,
                              request.begin() + data_offset + 64);

  spdlog::debug("U2F: Challenge: {:02x}",
                spdlog::to_hex(challenge.begin(), challenge.begin() + 8));
  spdlog::debug("U2F: AppID: {:02x}",
                spdlog::to_hex(app_id.begin(), app_id.begin() + 8));

  // 生成新的用户密钥对
  ECKeyPair user_key;
  if (!user_key.generate()) {
    spdlog::error("U2F: 无法生成用户密钥对");
    return {0x6A, 0x80};
  }

  std::vector<uint8_t> public_key = user_key.get_public_key();
  std::vector<uint8_t> private_key = user_key.get_private_key();

  spdlog::debug("U2F: 生成用户密钥对，公钥 {} 字节", public_key.size());

  // 生成 key handle (包含加密的私钥信息)
  // 简化实现：key_handle = random_prefix(16) || private_key(32)
  // 实际产品应该用设备密钥加密
  std::vector<uint8_t> key_handle = CryptoUtils::random_bytes(16);
  key_handle.insert(key_handle.end(), private_key.begin(), private_key.end());

  // 保存凭据
  StoredCredential cred;
  cred.key_handle = key_handle;
  cred.private_key = private_key;
  cred.app_id = app_id;
  cred.counter = 0;
  credentials_[key_handle] = cred;

  spdlog::debug("U2F: 凭据已保存，key_handle {} 字节", key_handle.size());

  // 使用 attestation 证书
  if (attestation_cert_.empty()) {
    spdlog::error("U2F: Attestation 证书不可用");
    return {0x6A, 0x80};
  }

  // 构造签名数据: 00 || app_id || challenge || key_handle || public_key
  std::vector<uint8_t> sig_data;
  sig_data.push_back(0x00);
  sig_data.insert(sig_data.end(), app_id.begin(), app_id.end());
  sig_data.insert(sig_data.end(), challenge.begin(), challenge.end());
  sig_data.insert(sig_data.end(), key_handle.begin(), key_handle.end());
  sig_data.insert(sig_data.end(), public_key.begin(), public_key.end());

  // 使用 attestation 密钥签名
  std::vector<uint8_t> signature = attestation_key_.sign(sig_data);
  if (signature.empty()) {
    spdlog::error("U2F: 签名失败");
    return {0x6A, 0x80};
  }

  spdlog::debug("U2F: 签名生成完成，{} 字节", signature.size());

  // 构造响应
  // Format: 0x05 || public_key(65) || key_handle_len(1) || key_handle || cert
  // || sig || 0x9000
  std::vector<uint8_t> response;
  response.push_back(0x05);  // Reserved byte
  response.insert(response.end(), public_key.begin(), public_key.end());
  response.push_back(static_cast<uint8_t>(key_handle.size()));
  response.insert(response.end(), key_handle.begin(), key_handle.end());
  response.insert(response.end(), attestation_cert_.begin(),
                  attestation_cert_.end());
  response.insert(response.end(), signature.begin(), signature.end());
  response.push_back(0x90);  // SW_NO_ERROR
  response.push_back(0x00);

  spdlog::debug("U2F: 注册响应生成完成 ({} 字节)", response.size());
  return response;
}

std::vector<uint8_t> FIDO2Device::generate_u2f_auth_response(
    const std::vector<uint8_t>& request) {
  spdlog::debug("U2F: 生成认证响应 (使用真实加密)");

  // U2F Authenticate 请求格式:
  // challenge (32) || app_id (32) || key_handle_len (1) || key_handle

  if (request.size() < 7 + 65) {
    return {0x6A, 0x80};  // SW_WRONG_LENGTH
  }

  size_t data_offset = 7;
  std::vector<uint8_t> challenge(request.begin() + data_offset,
                                 request.begin() + data_offset + 32);
  std::vector<uint8_t> app_id(request.begin() + data_offset + 32,
                              request.begin() + data_offset + 64);
  uint8_t key_handle_len = request[data_offset + 64];

  if (request.size() < data_offset + 65 + key_handle_len) {
    return {0x6A, 0x80};
  }

  std::vector<uint8_t> key_handle(
      request.begin() + data_offset + 65,
      request.begin() + data_offset + 65 + key_handle_len);

  spdlog::debug("U2F: App ID: {:02x}",
                spdlog::to_hex(app_id.begin(), app_id.begin() + 8));
  spdlog::debug("U2F: Key Handle 长度: {}", key_handle_len);

  // 查找凭据 (通过 key_handle)
  auto it = credentials_.find(key_handle);
  if (it == credentials_.end()) {
    spdlog::debug("U2F: 未找到凭据 (key_handle 不匹配)");

    // 验证 app_id 是否匹配
    for (const auto& [stored_handle, cred] : credentials_) {
      if (cred.app_id == app_id) {
        spdlog::debug("U2F: 找到匹配 app_id 的凭据");
        // 检查 key_handle 中存储的私钥
        if (key_handle.size() >= 48) {
          // key_handle = random(16) || private_key(32)
          std::vector<uint8_t> extracted_private_key(key_handle.begin() + 16,
                                                     key_handle.end());

          // 用提取的私钥创建 key pair 进行签名
          ECKeyPair user_key;
          if (user_key.set_private_key(extracted_private_key)) {
            it = credentials_.end();  // 使用提取的密钥

            // 增加计数器
            uint32_t counter = ++const_cast<StoredCredential&>(cred).counter;

            // 构造签名数据: app_id || user_presence || counter || challenge
            std::vector<uint8_t> sig_data;
            sig_data.insert(sig_data.end(), app_id.begin(), app_id.end());
            sig_data.push_back(0x01);  // user presence = true
            sig_data.push_back((counter >> 24) & 0xFF);
            sig_data.push_back((counter >> 16) & 0xFF);
            sig_data.push_back((counter >> 8) & 0xFF);
            sig_data.push_back(counter & 0xFF);
            sig_data.insert(sig_data.end(), challenge.begin(), challenge.end());

            std::vector<uint8_t> signature = user_key.sign(sig_data);
            if (signature.empty()) {
              spdlog::error("U2F: 签名失败");
              return {0x6A, 0x80};
            }

            // 响应: user_presence(1) || counter(4) || signature || 0x9000
            std::vector<uint8_t> response;
            response.push_back(0x01);  // user presence
            response.push_back((counter >> 24) & 0xFF);
            response.push_back((counter >> 16) & 0xFF);
            response.push_back((counter >> 8) & 0xFF);
            response.push_back(counter & 0xFF);
            response.insert(response.end(), signature.begin(), signature.end());
            response.push_back(0x90);
            response.push_back(0x00);

            spdlog::debug("U2F: 认证响应生成完成 ({} 字节)", response.size());
            return response;
          }
        }
      }
    }

    return {0x6A, 0x88};  // SW_WRONG_DATA - credential not found
  }

  // 找到了存储的凭据
  it->second.counter++;
  uint32_t counter = it->second.counter;

  // 保存到 TPM (计数器已更新)
  save_credentials_to_tpm();

  // 重建用户密钥
  ECKeyPair user_key;
  if (!user_key.set_private_key(it->second.private_key)) {
    spdlog::error("U2F: 无法恢复用户密钥");
    return {0x6A, 0x80};
  }

  // 构造签名数据: app_id || user_presence || counter || challenge
  std::vector<uint8_t> sig_data;
  sig_data.insert(sig_data.end(), app_id.begin(), app_id.end());
  sig_data.push_back(0x01);  // user presence = true
  sig_data.push_back((counter >> 24) & 0xFF);
  sig_data.push_back((counter >> 16) & 0xFF);
  sig_data.push_back((counter >> 8) & 0xFF);
  sig_data.push_back(counter & 0xFF);
  sig_data.insert(sig_data.end(), challenge.begin(), challenge.end());

  // 使用用户私钥签名
  std::vector<uint8_t> signature = user_key.sign(sig_data);
  if (signature.empty()) {
    spdlog::error("U2F: 签名失败");
    return {0x6A, 0x80};
  }

  // 响应: user_presence(1) || counter(4) || signature || 0x9000
  std::vector<uint8_t> response;
  response.push_back(0x01);  // user presence
  response.push_back((counter >> 24) & 0xFF);
  response.push_back((counter >> 16) & 0xFF);
  response.push_back((counter >> 8) & 0xFF);
  response.push_back(counter & 0xFF);
  response.insert(response.end(), signature.begin(), signature.end());
  response.push_back(0x90);
  response.push_back(0x00);

  spdlog::debug("U2F: 认证响应生成完成 ({} 字节)", response.size());
  return response;
}

uint32_t FIDO2Device::allocate_channel_id() {
  std::uniform_int_distribution<uint32_t> dist(1, 0xFFFFFFFE);
  uint32_t cid;

  std::lock_guard<std::mutex> lock(channels_mutex_);
  do {
    cid = dist(rng_);
  } while (active_channels_.count(cid) > 0);

  return cid;
}

bool FIDO2Device::load_credentials_from_tpm() {
  if (!tpm_storage_.is_available()) {
    return false;
  }

  if (!tpm_storage_.has_sealed_data()) {
    spdlog::info("TPM: 没有已封装的凭据数据");
    return true;
  }

  auto data = tpm_storage_.unseal();
  if (!data) {
    spdlog::error("TPM: 无法解封凭据: {}", tpm_storage_.last_error());
    return false;
  }

  auto creds = CredentialSerializer::deserialize(*data);
  credentials_.clear();

  for (const auto& cred : creds) {
    StoredCredential stored;
    stored.key_handle = cred.credential_id;
    stored.private_key = cred.private_key;
    stored.app_id = cred.app_id;
    stored.user_id = cred.user_id;
    stored.user_name = cred.user_name;
    stored.rp_id = cred.rp_id;
    stored.counter = cred.counter;
    credentials_[cred.credential_id] = std::move(stored);
  }

  spdlog::info("TPM: 已加载 {} 个凭据", credentials_.size());
  return true;
}

bool FIDO2Device::save_credentials_to_tpm() {
  if (!tpm_storage_.is_available()) {
    spdlog::warn("TPM: 存储不可用，凭据未保存");
    return false;
  }

  std::vector<CredentialSerializer::Credential> creds;
  creds.reserve(credentials_.size());

  for (const auto& [id, stored] : credentials_) {
    CredentialSerializer::Credential cred;
    cred.credential_id = stored.key_handle;
    cred.private_key = stored.private_key;
    cred.app_id = stored.app_id;
    cred.user_id = stored.user_id;
    cred.user_name = stored.user_name;
    cred.rp_id = stored.rp_id;
    cred.counter = stored.counter;
    creds.push_back(std::move(cred));
  }

  auto data = CredentialSerializer::serialize(creds);

  if (!tpm_storage_.seal(data)) {
    spdlog::error("TPM: 凭据封装失败: {}", tpm_storage_.last_error());
    return false;
  }

  spdlog::info("TPM: 已保存 {} 个凭据到 TPM", credentials_.size());
  return true;
}

}  // namespace howdy
