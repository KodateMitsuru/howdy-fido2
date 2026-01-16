#include "pam_auth.h"

#include <pwd.h>
#include <security/pam_appl.h>
#include <spdlog/spdlog.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <future>
#include <thread>

namespace howdy {

// PAM 会话数据
struct PAMConvData {
  PAMPromptCallback* prompt_callback;
};

// PAM 会话回调函数
static int pam_conversation(int num_msg, const struct pam_message** msg,
                            struct pam_response** resp, void* appdata_ptr) {
  auto* conv_data = static_cast<PAMConvData*>(appdata_ptr);

  // 分配响应数组
  *resp = static_cast<pam_response*>(calloc(num_msg, sizeof(pam_response)));
  if (*resp == nullptr) {
    return PAM_BUF_ERR;
  }

  for (int i = 0; i < num_msg; ++i) {
    const auto* m = msg[i];

    switch (m->msg_style) {
      case PAM_PROMPT_ECHO_OFF:
      case PAM_PROMPT_ECHO_ON:
        (*resp)[i].resp = strdup("");
        (*resp)[i].resp_retcode = 0;
        break;

      case PAM_ERROR_MSG:
        spdlog::error("PAM Error: {}", m->msg);
        (*resp)[i].resp = nullptr;
        (*resp)[i].resp_retcode = 0;
        break;

      case PAM_TEXT_INFO:
        spdlog::debug("PAM Info: {}", m->msg);
        if (conv_data && conv_data->prompt_callback &&
            *conv_data->prompt_callback) {
          (*conv_data->prompt_callback)(m->msg);
        }
        (*resp)[i].resp = nullptr;
        (*resp)[i].resp_retcode = 0;
        break;

      default:
        // 未知消息类型
        (*resp)[i].resp = nullptr;
        (*resp)[i].resp_retcode = 0;
        break;
    }
  }

  return PAM_SUCCESS;
}

PAMAuthenticator::PAMAuthenticator(const std::string& service_name)
    : service_name_(service_name) {}

PAMAuthenticator::~PAMAuthenticator() = default;

PAMResult PAMAuthenticator::authenticate(const std::string& username) {
  std::string user = username;

  // 如果未指定用户名，获取当前用户
  if (user.empty()) {
    uid_t uid = getuid();
    struct passwd* pw = getpwuid(uid);
    if (pw != nullptr) {
      user = pw->pw_name;
    } else {
      last_error_ = "无法获取当前用户名";
      return PAMResult::ERROR;
    }
  }

  spdlog::debug("PAM: 开始验证用户 '{}' (服务: {})", user, service_name_);

  // 使用异步执行 PAM 验证，以支持超时
  // 注意: 使用值捕获 user，避免引用悬空
  auto future = std::async(std::launch::async, [this, user]() -> PAMResult {
    pam_handle_t* pamh = nullptr;

    PAMConvData conv_data;
    conv_data.prompt_callback = &prompt_callback_;

    struct pam_conv conv = {pam_conversation, &conv_data};

    // 初始化 PAM
    int ret = pam_start(service_name_.c_str(), user.c_str(), &conv, &pamh);
    if (ret != PAM_SUCCESS) {
      last_error_ = std::string("pam_start 失败: ") + pam_strerror(pamh, ret);
      spdlog::error("PAM: {}", last_error_);
      return PAMResult::ERROR;
    }

    pam_set_item(pamh, PAM_TTY, "/dev/console");
    pam_set_item(pamh, PAM_RHOST, "localhost");
    pam_set_item(pamh, PAM_RUSER, user.c_str());

    spdlog::debug("PAM: 等待验证...");
    ret = pam_authenticate(pamh, 0);

    PAMResult result;
    if (ret == PAM_SUCCESS) {
      spdlog::debug("PAM: ✓ 验证成功!");
      result = PAMResult::SUCCESS;
    } else if (ret == PAM_AUTH_ERR) {
      last_error_ = "验证失败";
      spdlog::debug("PAM: ✗ 验证失败");
      result = PAMResult::AUTH_FAILED;
    } else if (ret == PAM_USER_UNKNOWN) {
      last_error_ = "用户不存在";
      spdlog::debug("PAM: ✗ 用户不存在");
      result = PAMResult::AUTH_FAILED;
    } else if (ret == PAM_MAXTRIES) {
      last_error_ = "达到最大尝试次数";
      spdlog::debug("PAM: ✗ 达到最大尝试次数");
      result = PAMResult::AUTH_FAILED;
    } else {
      last_error_ = std::string("PAM 错误 (") + std::to_string(ret) +
                    "): " + pam_strerror(pamh, ret);
      spdlog::error("PAM: {}", last_error_);
      result = PAMResult::ERROR;
    }

    // 清理
    pam_end(pamh, ret);
    return result;
  });

  // 等待超时
  auto status = future.wait_for(std::chrono::seconds(timeout_seconds_));
  if (status == std::future_status::timeout) {
    last_error_ = "验证超时";
    spdlog::warn("PAM: ✗ 验证超时 ({} 秒)", timeout_seconds_);
    return PAMResult::USER_CANCELLED;
  }

  return future.get();
}

}  // namespace howdy
