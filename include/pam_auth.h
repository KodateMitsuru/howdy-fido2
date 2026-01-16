#pragma once

#include <functional>
#include <string>

namespace howdy {

// PAM 验证结果
enum class PAMResult { SUCCESS, AUTH_FAILED, USER_CANCELLED, ERROR };

// PAM 验证回调（用于显示提示信息）
using PAMPromptCallback = std::function<void(const std::string&)>;

class PAMAuthenticator {
 public:
  PAMAuthenticator(const std::string& service_name = "howdy-fido2");
  ~PAMAuthenticator();

  // 执行 PAM 验证
  PAMResult authenticate(const std::string& username = "");

  // 设置超时时间（秒）
  void set_timeout(int seconds) { timeout_seconds_ = seconds; }

  // 设置提示回调
  void set_prompt_callback(PAMPromptCallback callback) {
    prompt_callback_ = std::move(callback);
  }

  // 获取最后的错误信息
  const std::string& last_error() const { return last_error_; }

 private:
  std::string service_name_;
  int timeout_seconds_ = 30;
  std::string last_error_;
  PAMPromptCallback prompt_callback_;
};

}  // namespace howdy
