#include "dbus_interface.h"

#include <spdlog/spdlog.h>

#include <chrono>

namespace howdy {

// ==================== DBusServer 实现 ====================

DBusServer::DBusServer() = default;

DBusServer::~DBusServer() { stop(); }

bool DBusServer::start() {
  try {
    // 连接到系统总线并请求服务名称
    connection_ =
        sdbus::createSystemBusConnection(sdbus::ServiceName{DBUS_SERVICE_NAME});

    // 创建对象
    object_ =
        sdbus::createObject(*connection_, sdbus::ObjectPath{DBUS_OBJECT_PATH});

    // Auth 接口
    object_
        ->addVTable(sdbus::registerMethod("SubmitAuthResult")
                        .implementedAs([this](bool success) {
                          handle_submit_auth_result(success);
                        })
                        .withInputParamNames("success"),
                    sdbus::registerMethod("GetPendingAuth")
                        .implementedAs(
                            [this]() -> std::tuple<std::string, std::string> {
                              return handle_get_pending_auth();
                            })
                        .withOutputParamNames("operation", "rp_id"),
                    sdbus::registerSignal("AuthRequired")
                        .withParameters<std::string, std::string>())
        .forInterface(DBUS_INTERFACE_AUTH);

    // TPM 接口
    object_
        ->addVTable(
            sdbus::registerMethod("SealData")
                .implementedAs([this](const std::vector<uint8_t>& data) {
                  return handle_seal_data(data);
                })
                .withInputParamNames("data")
                .withOutputParamNames("sealed_data"),
            sdbus::registerMethod("UnsealData")
                .implementedAs([this](const std::vector<uint8_t>& sealed) {
                  return handle_unseal_data(sealed);
                })
                .withInputParamNames("sealed_data")
                .withOutputParamNames("data"))
        .forInterface(DBUS_INTERFACE_TPM);

    // Credentials 接口
    object_
        ->addVTable(
            sdbus::registerMethod("LoadCredentials")
                .implementedAs([this](const std::vector<uint8_t>& data) {
                  return handle_load_credentials(data);
                })
                .withInputParamNames("sealed_data")
                .withOutputParamNames("success"),
            sdbus::registerMethod("GetCredentials")
                .implementedAs([this]() { return handle_get_credentials(); })
                .withOutputParamNames("sealed_data"),
            sdbus::registerSignal("CredentialsChanged"))
        .forInterface(DBUS_INTERFACE_CRED);

    spdlog::info("D-Bus: 服务已启动 ({})", DBUS_SERVICE_NAME);
    return true;

  } catch (const sdbus::Error& e) {
    spdlog::error("D-Bus: 启动失败 - {}", e.what());
    return false;
  }
}

void DBusServer::stop() {
  object_.reset();
  connection_.reset();
}

void DBusServer::process_events() {
  if (connection_) {
    connection_->processPendingEvent();
  }
}

bool DBusServer::request_auth(const std::string& operation,
                              const std::string& rp_id, int timeout_seconds) {
  if (!connection_ || !object_) {
    spdlog::error("D-Bus: 服务未启动");
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    waiting_for_auth_ = true;
    auth_result_ = false;
    current_operation_ = operation;
    current_rp_id_ = rp_id;
  }

  // 发送 AuthRequired 信号
  try {
    object_->emitSignal("AuthRequired")
        .onInterface(DBUS_INTERFACE_AUTH)
        .withArguments(operation, rp_id);
    spdlog::debug("D-Bus: 已发送 AuthRequired 信号");
  } catch (const sdbus::Error& e) {
    spdlog::error("D-Bus: 发送信号失败 - {}", e.what());
    return false;
  }

  // 处理 D-Bus 消息直到收到结果或超时
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);

  while (true) {
    {
      std::unique_lock<std::mutex> lock(auth_mutex_);
      if (!waiting_for_auth_) {
        return auth_result_;
      }
    }

    if (std::chrono::steady_clock::now() >= deadline) {
      spdlog::warn("D-Bus: 等待验证超时");
      std::lock_guard<std::mutex> lock(auth_mutex_);
      waiting_for_auth_ = false;
      return false;
    }

    // 处理 D-Bus 事件
    connection_->processPendingEvent();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

void DBusServer::notify_credentials_changed() {
  if (!object_) return;
  try {
    object_->emitSignal("CredentialsChanged").onInterface(DBUS_INTERFACE_CRED);
    spdlog::debug("D-Bus: 已发送 CredentialsChanged 信号");
  } catch (const sdbus::Error& e) {
    spdlog::error("D-Bus: 发送信号失败 - {}", e.what());
  }
}

bool DBusServer::handle_submit_auth_result(bool success) {
  std::lock_guard<std::mutex> lock(auth_mutex_);
  spdlog::debug("D-Bus: 收到验证结果: {}", success ? "成功" : "失败");
  auth_result_ = success;
  waiting_for_auth_ = false;
  auth_cv_.notify_all();
  return true;
}

std::tuple<std::string, std::string> DBusServer::handle_get_pending_auth() {
  std::lock_guard<std::mutex> lock(auth_mutex_);
  if (waiting_for_auth_) {
    return {current_operation_, current_rp_id_};
  }
  return {"", ""};
}

std::vector<uint8_t> DBusServer::handle_seal_data(
    const std::vector<uint8_t>& data) {
  if (tpm_seal_cb_) {
    return tpm_seal_cb_(data);
  }
  spdlog::error("D-Bus: TPM seal 回调未设置");
  return {};
}

std::vector<uint8_t> DBusServer::handle_unseal_data(
    const std::vector<uint8_t>& sealed) {
  if (tpm_unseal_cb_) {
    return tpm_unseal_cb_(sealed);
  }
  spdlog::error("D-Bus: TPM unseal 回调未设置");
  return {};
}

bool DBusServer::handle_load_credentials(const std::vector<uint8_t>& data) {
  if (cred_load_cb_) {
    return cred_load_cb_(data);
  }
  spdlog::error("D-Bus: 凭据加载回调未设置");
  return false;
}

std::vector<uint8_t> DBusServer::handle_get_credentials() {
  if (cred_get_cb_) {
    return cred_get_cb_();
  }
  spdlog::error("D-Bus: 凭据获取回调未设置");
  return {};
}

// ==================== DBusClient 实现 ====================

DBusClient::DBusClient() = default;

DBusClient::~DBusClient() { disconnect(); }

bool DBusClient::connect() {
  try {
    // 连接到系统总线
    connection_ = sdbus::createSystemBusConnection();

    // 创建代理
    proxy_ =
        sdbus::createProxy(*connection_, sdbus::ServiceName{DBUS_SERVICE_NAME},
                           sdbus::ObjectPath{DBUS_OBJECT_PATH});

    // 订阅 Auth 信号
    proxy_->uponSignal("AuthRequired")
        .onInterface(DBUS_INTERFACE_AUTH)
        .call([this](const std::string& operation, const std::string& rp_id) {
          on_auth_required(operation, rp_id);
        });

    // 订阅 Credentials 信号
    proxy_->uponSignal("CredentialsChanged")
        .onInterface(DBUS_INTERFACE_CRED)
        .call([this]() { on_credentials_changed(); });

    spdlog::info("D-Bus: 客户端已连接");
    return true;

  } catch (const sdbus::Error& e) {
    spdlog::error("D-Bus: 连接失败 - {}", e.what());
    return false;
  }
}

void DBusClient::disconnect() {
  proxy_.reset();
  connection_.reset();
}

void DBusClient::run() {
  if (!connection_) {
    spdlog::error("D-Bus: 未连接");
    return;
  }

  if (!running_) {
    running_ = true;
    spdlog::info("D-Bus: 客户端开始监听...");
  }

  try {
    // 检查是否有待处理的验证请求
    std::string operation, rp_id;
    proxy_->callMethod("GetPendingAuth")
        .onInterface(DBUS_INTERFACE_AUTH)
        .storeResultsTo(operation, rp_id);

    if (!operation.empty()) {
      on_auth_required(operation, rp_id);
    }

    // 处理 D-Bus 事件
    connection_->processPendingEvent();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

  } catch (const sdbus::Error& e) {
    // 服务可能暂时不可用
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}

void DBusClient::stop() { running_ = false; }

std::vector<uint8_t> DBusClient::seal_data(const std::vector<uint8_t>& data) {
  if (!proxy_) return {};
  try {
    std::vector<uint8_t> result;
    proxy_->callMethod("SealData")
        .onInterface(DBUS_INTERFACE_TPM)
        .withArguments(data)
        .storeResultsTo(result);
    return result;
  } catch (const sdbus::Error& e) {
    spdlog::error("D-Bus: SealData 失败 - {}", e.what());
    return {};
  }
}

std::vector<uint8_t> DBusClient::unseal_data(
    const std::vector<uint8_t>& sealed_data) {
  if (!proxy_) return {};
  try {
    std::vector<uint8_t> result;
    proxy_->callMethod("UnsealData")
        .onInterface(DBUS_INTERFACE_TPM)
        .withArguments(sealed_data)
        .storeResultsTo(result);
    return result;
  } catch (const sdbus::Error& e) {
    spdlog::error("D-Bus: UnsealData 失败 - {}", e.what());
    return {};
  }
}

bool DBusClient::load_credentials(const std::vector<uint8_t>& sealed_data) {
  if (!proxy_) return false;
  try {
    bool result = false;
    proxy_->callMethod("LoadCredentials")
        .onInterface(DBUS_INTERFACE_CRED)
        .withArguments(sealed_data)
        .storeResultsTo(result);
    return result;
  } catch (const sdbus::Error& e) {
    spdlog::error("D-Bus: LoadCredentials 失败 - {}", e.what());
    return false;
  }
}

std::vector<uint8_t> DBusClient::get_credentials() {
  if (!proxy_) return {};
  try {
    std::vector<uint8_t> result;
    proxy_->callMethod("GetCredentials")
        .onInterface(DBUS_INTERFACE_CRED)
        .storeResultsTo(result);
    return result;
  } catch (const sdbus::Error& e) {
    spdlog::error("D-Bus: GetCredentials 失败 - {}", e.what());
    return {};
  }
}

void DBusClient::on_auth_required(const std::string& operation,
                                  const std::string& rp_id) {
  spdlog::info("D-Bus: 收到验证请求 - {} ({})", operation, rp_id);

  bool success = false;
  if (pam_callback_) {
    success = pam_callback_(operation, rp_id);
  }

  // 发送结果
  try {
    proxy_->callMethod("SubmitAuthResult")
        .onInterface(DBUS_INTERFACE_AUTH)
        .withArguments(success);
    spdlog::debug("D-Bus: 已提交验证结果: {}", success ? "成功" : "失败");
  } catch (const sdbus::Error& e) {
    spdlog::error("D-Bus: 提交结果失败 - {}", e.what());
  }
}

void DBusClient::on_credentials_changed() {
  spdlog::info("D-Bus: 凭据已变更");
  if (cred_changed_cb_) {
    cred_changed_cb_();
  }
}

}  // namespace howdy
