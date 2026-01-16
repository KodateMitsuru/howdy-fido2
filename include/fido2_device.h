#pragma once

#include <map>
#include <mutex>
#include <random>

#include "crypto.h"
#include "pam_auth.h"
#include "tpm_storage.h"
#include "uhid_device.h"

namespace howdy {

// 用于组装分片消息的结构
struct PendingMessage {
  uint32_t channel_id;
  uint8_t cmd;
  uint16_t total_len;
  std::vector<uint8_t> data;
  uint8_t expected_seq;
};

class FIDO2Device {
 public:
  FIDO2Device();
  ~FIDO2Device();

  // 启动/停止设备
  bool start();
  void stop();
  bool is_running() const { return uhid_.is_running(); }

  // 设置 PAM 服务名
  void set_pam_service(const std::string& service) { pam_service_ = service; }

 private:
  // CTAPHID 协议处理
  void handle_ctaphid_message(const std::vector<uint8_t>& data);
  void handle_init(uint32_t channel_id, const uint8_t* nonce);
  void handle_ping(uint32_t channel_id, const std::vector<uint8_t>& data);
  void handle_cbor(uint32_t channel_id, const std::vector<uint8_t>& data);
  void handle_msg(uint32_t channel_id,
                  const std::vector<uint8_t>& data);  // U2F
  void handle_wink(uint32_t channel_id);

  // CTAP2 命令处理
  std::vector<uint8_t> handle_get_info();
  std::vector<uint8_t> handle_make_credential(
      const std::vector<uint8_t>& cbor_data);
  std::vector<uint8_t> handle_get_assertion(
      const std::vector<uint8_t>& cbor_data);

  // U2F 响应生成
  std::vector<uint8_t> generate_u2f_register_response(
      const std::vector<uint8_t>& request);
  std::vector<uint8_t> generate_u2f_auth_response(
      const std::vector<uint8_t>& request);

  // PAM 验证
  bool verify_user(const std::string& operation);

  // 发送响应
  void send_response(uint32_t channel_id, CTAPHIDCommand cmd,
                     const std::vector<uint8_t>& data);
  void send_error(uint32_t channel_id, CTAPHIDError error);

  // 生成新的通道ID
  uint32_t allocate_channel_id();

  // 处理完整消息
  void process_complete_message(uint32_t channel_id, uint8_t cmd,
                                const std::vector<uint8_t>& data);

  UHIDDevice uhid_;
  std::map<uint32_t, bool> active_channels_;
  std::map<uint32_t, PendingMessage> pending_messages_;
  std::mutex channels_mutex_;
  std::mt19937 rng_;

  // 存储的凭据 (credential_id -> credential)
  struct StoredCredential {
    std::vector<uint8_t> key_handle;
    std::vector<uint8_t> private_key;  // P-256 私钥 (32 字节)
    std::vector<uint8_t> app_id;       // RP ID 的 SHA-256 hash
    std::vector<uint8_t> user_id;      // 用户 ID
    std::string user_name;             // 用户名
    std::string rp_id;                 // RP ID (原始字符串)
    uint32_t counter = 0;
  };
  std::map<std::vector<uint8_t>, StoredCredential>
      credentials_;  // credential_id -> credential

  // Attestation 密钥对 (用于签署注册响应)
  ECKeyPair attestation_key_;
  std::vector<uint8_t> attestation_cert_;

  // TPM 存储
  TPMStorage tpm_storage_;
  bool load_credentials_from_tpm();
  bool save_credentials_to_tpm();

  // PAM 服务名
  std::string pam_service_ = "howdy-fido2";

  // 用户验证状态缓存
  bool user_verified_ = false;
  std::chrono::steady_clock::time_point verification_time_;
  static constexpr int VERIFICATION_TIMEOUT_SECONDS = 30;
  std::mutex verification_mutex_;
  bool verification_in_progress_ = false;
};

}  // namespace howdy
