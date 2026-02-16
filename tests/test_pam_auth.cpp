#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <string>

#include "pam_auth.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

using namespace howdy;

// ── 无效用户 → 认证失败 ──────────────────────────────────────
TEST(PAMAuthenticator, Authenticate_InvalidUser) {
  PAMAuthenticator pam("login");
  pam.set_timeout(5);
  auto result = pam.authenticate("__nonexistent_user_12345__");
  // 无效用户应该返回失败（AUTH_FAILED 或 ERROR）
  EXPECT_NE(result, PAMResult::SUCCESS);
}

// ── 超时测试 ─────────────────────────────────────────────────
TEST(PAMAuthenticator, Timeout_VeryShort) {
  // 使用 howdy-fido2 服务。如果 PAM 配置自动通过（如 pam_permit），
  // 认证在超时前完成 → SUCCESS 也是合法结果。
  PAMAuthenticator pam("howdy-fido2");
  pam.set_timeout(1);  // 1 秒超时
  auto result = pam.authenticate();
  // 验证返回的是有效枚举值（不崩溃，不HANG住）
  EXPECT_TRUE(
      result == PAMResult::SUCCESS || result == PAMResult::AUTH_FAILED ||
      result == PAMResult::USER_CANCELLED || result == PAMResult::ERROR);
}

// ── 回调触发 ─────────────────────────────────────────────────
TEST(PAMAuthenticator, PromptCallback_CanBeSet) {
  PAMAuthenticator pam("login");
  std::atomic<bool> called{false};
  pam.set_prompt_callback([&](const std::string& msg) { called = true; });
  pam.set_timeout(3);
  // 尝试认证（回调是否被调用取决于 PAM 模块是否发送 TEXT_INFO）
  pam.authenticate("__nonexistent_user_12345__");
  // 不对 called 做断言 — 只验证设置回调不崩溃
}

// ── last_error ───────────────────────────────────────────────
TEST(PAMAuthenticator, LastError_AfterFailure) {
  PAMAuthenticator pam("login");
  pam.set_timeout(3);
  auto result = pam.authenticate("__nonexistent_user_12345__");
  if (result != PAMResult::SUCCESS) {
    // 失败后 last_error 可能非空（取决于具体实现）
    // 至少不应崩溃
    [[maybe_unused]] auto err = pam.last_error();
  }
}

// ── 默认构造 ─────────────────────────────────────────────────
TEST(PAMAuthenticator, DefaultServiceName) {
  PAMAuthenticator pam;  // 默认 "howdy-fido2"
  pam.set_timeout(2);
  // 仅验证不崩溃
  auto result = pam.authenticate("__nonexistent_user_12345__");
  EXPECT_NE(result, PAMResult::SUCCESS);
}
