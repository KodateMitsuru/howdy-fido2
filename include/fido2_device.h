#pragma once

#include <array>
#include <concepts>
#include <flat_map>
#include <flat_set>
#include <functional>
#include <mutex>
#include <random>
#include <span>

#include "crypto.h"
#include "uhid_device.h"

namespace howdy {

// FIDO2 AAGUID (唯一设备标识)
inline constexpr std::array<uint8_t, 16> AAGUID = {'H', 'O', 'W', 'D', 'Y', 'F',
                                                   'I', 'D', 'O', '2', 'D', 'E',
                                                   'V', 'I', 'C', 'E'};

// 外部验证回调类型：返回 true 表示验证成功
using AuthHandler =
    std::function<bool(const std::string& operation, const std::string& rp_id)>;

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

  // 设置外部验证回调（用于 D-Bus 模式）
  template <typename F>
    requires std::invocable<F, const std::string&, const std::string&> &&
             std::convertible_to<std::invoke_result_t<F, const std::string&,
                                                      const std::string&>,
                                 bool>
  void set_auth_handler(F&& handler) {
    auth_handler_ = std::forward<F>(handler);
  }

  // 设置 PAM 服务名（用于内置 PAM 模式）
  void set_pam_service(const std::string& service) { pam_service_ = service; }

 private:
  // CTAPHID 协议处理
  void handle_ctaphid_message(const std::vector<uint8_t>& data);
  void handle_init(uint32_t channel_id, std::span<const uint8_t, 8> nonce);
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
  std::flat_set<uint32_t> active_channels_;
  std::flat_map<uint32_t, PendingMessage> pending_messages_;
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
  std::flat_map<std::vector<uint8_t>, StoredCredential>
      credentials_;  // credential_id -> credential

  // Attestation 密钥对 (用于签署注册响应)
  ECKeyPair attestation_key_;
  std::vector<uint8_t> attestation_cert_;

 public:
  // 凭据数据操作（D-Bus 模式使用）
  using CredentialsChangedCallback = std::function<void()>;

  bool load_credentials_from_data(const std::vector<uint8_t>& data);
  std::vector<uint8_t> get_credentials_data();
  template <typename F>
    requires std::invocable<F>
  void set_credentials_changed_callback(F&& cb) {
    credentials_changed_cb_ = std::forward<F>(cb);
  }

 private:
  CredentialsChangedCallback credentials_changed_cb_;
  void notify_credentials_changed();

  // 验证相关
  AuthHandler auth_handler_;                 // 外部验证回调（D-Bus 模式）
  std::string pam_service_ = "howdy-fido2";  // PAM 服务名（内置模式）
  std::string current_rp_id_;                // 当前 RP ID

  // 用户验证状态缓存
  bool user_verified_ = false;
  std::chrono::steady_clock::time_point verification_time_;
  static constexpr int VERIFICATION_TIMEOUT_SECONDS = 30;
  std::mutex verification_mutex_;
  bool verification_in_progress_ = false;
};

}  // namespace howdy
