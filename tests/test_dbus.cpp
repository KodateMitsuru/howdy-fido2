#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include "dbus_interface.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

using namespace howdy;

// ── Fixture: 需要 D-Bus 系统总线 + 策略文件 ──────────────────
class DBusTest : public ::testing::Test {
 protected:
  DBusServer server;
  DBusClient client;
  std::vector<uint8_t> last_sealed;
  std::vector<uint8_t> stored_credentials;

  // 后台事件循环
  std::atomic<bool> event_loop_running_{false};
  std::thread event_loop_thread_;

  void SetUp() override {
    // 设置 mock 回调
    server.set_tpm_seal_callback(
        [](const std::vector<uint8_t>& data) -> std::vector<uint8_t> {
          return data;
        });
    server.set_tpm_unseal_callback(
        [](const std::vector<uint8_t>& data) -> std::vector<uint8_t> {
          return data;
        });
    server.set_credentials_load_callback(
        [this](const std::vector<uint8_t>& data) -> bool {
          stored_credentials = data;
          return true;
        });
    server.set_credentials_get_callback(
        [this]() -> std::vector<uint8_t> { return stored_credentials; });

    if (!server.start()) {
      GTEST_SKIP() << "Cannot start D-Bus server — check system bus access "
                      "and policy file";
    }

    // 启动后台事件循环（等同于 daemon_main 的 while 循环）
    event_loop_running_ = true;
    event_loop_thread_ = std::thread([this]() {
      while (event_loop_running_) {
        server.process_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    });

    // 给 server 一点时间注册服务名
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (!client.connect()) {
      event_loop_running_ = false;
      event_loop_thread_.join();
      server.stop();
      GTEST_SKIP() << "Cannot connect D-Bus client";
    }
  }

  void TearDown() override {
    client.disconnect();
    event_loop_running_ = false;
    if (event_loop_thread_.joinable()) event_loop_thread_.join();
    server.stop();
  }
};

// ── Server start / Client connect ────────────────────────────
TEST_F(DBusTest, ServerStart_ClientConnect) {
  EXPECT_TRUE(client.is_connected());
}

// ── Ping ─────────────────────────────────────────────────────
TEST_F(DBusTest, Ping_Success) { EXPECT_TRUE(client.ping()); }

// ── SealData roundtrip ───────────────────────────────────────
TEST_F(DBusTest, SealData_Roundtrip) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
  auto result = client.seal_data(data);
  EXPECT_EQ(result, data);  // mock seal 返回原数据
}

TEST_F(DBusTest, SealData_Empty) {
  auto result = client.seal_data({});
  EXPECT_TRUE(result.empty());
}

TEST_F(DBusTest, SealData_Large) {
  std::vector<uint8_t> data(4096, 0xAA);
  auto result = client.seal_data(data);
  EXPECT_EQ(result, data);
}

// ── UnsealData roundtrip ─────────────────────────────────────
TEST_F(DBusTest, UnsealData_Roundtrip) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  auto result = client.unseal_data(data);
  EXPECT_EQ(result, data);
}

TEST_F(DBusTest, UnsealData_ServiceError) {
  // 停止 server，让 client 调用失败
  server.stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  bool service_error = false;
  auto result = client.unseal_data({0x01}, &service_error);
  // 服务不可用时应失败
  EXPECT_TRUE(result.empty() || service_error);
}

// ── LoadCredentials + GetCredentials ─────────────────────────
TEST_F(DBusTest, LoadGetCredentials_Roundtrip) {
  std::vector<uint8_t> cred_data = {0x10, 0x20, 0x30, 0x40, 0x50};
  EXPECT_TRUE(client.load_credentials(cred_data));

  auto got = client.get_credentials();
  EXPECT_EQ(got, cred_data);
}

// ── CredentialsChanged 信号 ──────────────────────────────────
TEST_F(DBusTest, CredentialsChanged_Signal) {
  std::atomic<bool> signal_received{false};
  client.set_credentials_changed_callback([&]() { signal_received = true; });

  // 给信号注册一点时间
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  server.notify_credentials_changed();

  // 等待信号传递（同时 pump client 连接的事件循环以接收信号）
  for (int i = 0; i < 50 && !signal_received; ++i) {
    client.run();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  EXPECT_TRUE(signal_received);
}

// ── ServiceNotReady ──────────────────────────────────────────
TEST(DBusClientNoServer, Ping_NoServer) {
  DBusClient client;
  if (!client.connect()) {
    GTEST_SKIP() << "Cannot connect to system bus";
  }
  // 没有 server 运行时 ping 应该失败或超时
  // 如果另一个 howdy-fido2-daemon 正在运行，这个测试行为不确定
  // 所以只验证不崩溃
  [[maybe_unused]] auto ok = client.ping();
}
