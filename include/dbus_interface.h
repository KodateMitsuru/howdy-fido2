#pragma once

#include <sdbus-c++/sdbus-c++.h>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace howdy {

// D-Bus 服务信息
constexpr const char* DBUS_SERVICE_NAME = "org.howdy.Fido2";
constexpr const char* DBUS_OBJECT_PATH = "/org/howdy/Fido2";
constexpr const char* DBUS_INTERFACE_AUTH = "org.howdy.Fido2.Auth";
constexpr const char* DBUS_INTERFACE_TPM = "org.howdy.Fido2.TPM";
constexpr const char* DBUS_INTERFACE_CRED = "org.howdy.Fido2.Credentials";

/**
 * D-Bus 服务端（运行在守护进程中 - 需要高权限）
 *
 * Auth 接口:
 * - SubmitAuthResult(success) - 客户端提交验证结果
 * - GetPendingAuth() -> (operation, rp_id) - 获取待处理的验证请求
 * - Signal: AuthRequired(operation, rp_id) - 需要验证时发送
 *
 * TPM 接口:
 * - SealData(data) -> sealed_data - 用 TPM 封装数据
 * - UnsealData(sealed_data) -> data - 用 TPM 解封数据
 *
 * Credentials 接口:
 * - LoadCredentials(sealed_data) - 客户端上传加密凭据
 * - GetCredentials() -> sealed_data - 获取当前凭据（TPM 加密）
 * - Signal: CredentialsChanged() - 凭据变更时发送
 */
class DBusServer {
 public:
  // 回调类型
  using AuthCallback = std::function<bool(const std::string& operation,
                                          const std::string& rp_id)>;
  using TPMSealCallback =
      std::function<std::vector<uint8_t>(const std::vector<uint8_t>& data)>;
  using TPMUnsealCallback = std::function<std::vector<uint8_t>(
      const std::vector<uint8_t>& sealed_data)>;
  using CredentialsLoadCallback =
      std::function<bool(const std::vector<uint8_t>& data)>;
  using CredentialsGetCallback = std::function<std::vector<uint8_t>()>;

  DBusServer();
  ~DBusServer();

  // 启动 D-Bus 服务
  bool start();
  void stop();

  // 处理 D-Bus 事件（需要在主循环中调用）
  void process_events();

  // 请求验证（发送信号并等待客户端响应）
  bool request_auth(const std::string& operation, const std::string& rp_id,
                    int timeout_seconds = 60);

  // 通知凭据变更
  void notify_credentials_changed();

  // 设置回调
  void set_tpm_seal_callback(TPMSealCallback cb) {
    tpm_seal_cb_ = std::move(cb);
  }
  void set_tpm_unseal_callback(TPMUnsealCallback cb) {
    tpm_unseal_cb_ = std::move(cb);
  }
  void set_credentials_load_callback(CredentialsLoadCallback cb) {
    cred_load_cb_ = std::move(cb);
  }
  void set_credentials_get_callback(CredentialsGetCallback cb) {
    cred_get_cb_ = std::move(cb);
  }

 private:
  std::unique_ptr<sdbus::IConnection> connection_;
  std::unique_ptr<sdbus::IObject> object_;

  // 回调
  AuthCallback auth_callback_;
  TPMSealCallback tpm_seal_cb_;
  TPMUnsealCallback tpm_unseal_cb_;
  CredentialsLoadCallback cred_load_cb_;
  CredentialsGetCallback cred_get_cb_;

  // 当前验证状态
  bool waiting_for_auth_ = false;
  bool auth_result_ = false;
  std::string current_operation_;
  std::string current_rp_id_;
  std::mutex auth_mutex_;
  std::condition_variable auth_cv_;

  // D-Bus 方法处理
  bool handle_submit_auth_result(bool success);
  std::tuple<std::string, std::string> handle_get_pending_auth();
  std::vector<uint8_t> handle_seal_data(const std::vector<uint8_t>& data);
  std::vector<uint8_t> handle_unseal_data(const std::vector<uint8_t>& sealed);
  bool handle_load_credentials(const std::vector<uint8_t>& data);
  std::vector<uint8_t> handle_get_credentials();
};

/**
 * D-Bus 客户端（运行在用户进程中）
 *
 * - 监听 AuthRequired 信号，执行 PAM 验证
 * - 管理本地凭据文件（~/.local/share/howdy-fido2/）
 * - 通过 D-Bus 使用 TPM 加密/解密
 */
class DBusClient {
 public:
  // 回调类型
  using PAMCallback = std::function<bool(const std::string& operation,
                                         const std::string& rp_id)>;
  using CredentialsChangedCallback = std::function<void()>;

  DBusClient();
  ~DBusClient();

  // 连接到 D-Bus
  bool connect();
  void disconnect();
  bool is_connected() const {
    return connection_ != nullptr && proxy_ != nullptr;
  }

  // 检查 daemon 服务是否就绪
  bool is_service_ready();

  // 设置回调
  void set_pam_callback(PAMCallback callback) {
    pam_callback_ = std::move(callback);
  }
  void set_credentials_changed_callback(CredentialsChangedCallback cb) {
    cred_changed_cb_ = std::move(cb);
  }

  // 运行事件循环（单次）
  void run();
  void stop();

  // TPM 操作（通过 D-Bus 调用 daemon）
  std::vector<uint8_t> seal_data(const std::vector<uint8_t>& data);

  // 解封数据，service_error 指示是否是服务不可用导致的失败
  std::vector<uint8_t> unseal_data(const std::vector<uint8_t>& sealed_data,
                                   bool* service_error = nullptr);

  // 凭据操作
  bool load_credentials(const std::vector<uint8_t>& sealed_data);
  std::vector<uint8_t> get_credentials();

 private:
  std::unique_ptr<sdbus::IConnection> connection_;
  std::unique_ptr<sdbus::IProxy> proxy_;
  PAMCallback pam_callback_;
  CredentialsChangedCallback cred_changed_cb_;
  bool running_ = false;

  // 信号处理
  void on_auth_required(const std::string& operation, const std::string& rp_id);
  void on_credentials_changed();
};

}  // namespace howdy
