#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include "dbus_interface.h"
#include "fido2_device.h"
#include "tpm_storage.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

using namespace howdy;

// ── 全栈端到端 Fixture ───────────────────────────────────────
// 需要: root + TPM + D-Bus 系统总线 + 策略文件
class E2ETest : public ::testing::Test {
 protected:
  TPMStorage tpm;
  FIDO2Device fido;
  DBusServer server;
  DBusClient client;
  bool ready = false;

  // 后台事件循环
  std::atomic<bool> event_loop_running_{false};
  std::thread event_loop_thread_;

  void SetUp() override {
    // 1. 初始化 TPM
    if (!tpm.initialize()) {
      GTEST_SKIP() << "TPM not available: " << tpm.last_error();
    }

    // 2. 设置 FIDO2 device auth handler (始终成功)
    fido.set_auth_handler(
        [](const std::string&, const std::string&) -> bool { return true; });

    // 3. 绑定 D-Bus Server 回调到真实组件
    server.set_tpm_seal_callback(
        [this](const std::vector<uint8_t>& data) -> std::vector<uint8_t> {
          return tpm.seal_data(data);
        });
    server.set_tpm_unseal_callback(
        [this](const std::vector<uint8_t>& data) -> std::vector<uint8_t> {
          return tpm.unseal_data(data);
        });
    server.set_credentials_load_callback(
        [this](const std::vector<uint8_t>& data) -> bool {
          return fido.load_credentials_from_data(data);
        });
    server.set_credentials_get_callback([this]() -> std::vector<uint8_t> {
      return fido.get_credentials_data();
    });

    // 4. 启动 FIDO2 device
    if (!fido.start()) {
      GTEST_SKIP() << "Cannot start FIDO2Device (need root for /dev/uhid)";
    }

    // 5. 启动 D-Bus server
    if (!server.start()) {
      fido.stop();
      GTEST_SKIP() << "Cannot start D-Bus server";
    }

    // 启动后台事件循环
    event_loop_running_ = true;
    event_loop_thread_ = std::thread([this]() {
      while (event_loop_running_) {
        server.process_events();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 6. 连接 D-Bus client
    if (!client.connect()) {
      event_loop_running_ = false;
      event_loop_thread_.join();
      server.stop();
      fido.stop();
      GTEST_SKIP() << "Cannot connect D-Bus client";
    }

    ready = true;
  }

  void TearDown() override {
    if (ready) {
      client.disconnect();
      event_loop_running_ = false;
      if (event_loop_thread_.joinable()) event_loop_thread_.join();
      server.stop();
      fido.stop();
    }
  }
};

// ── TPM seal/unseal 通过 D-Bus ──────────────────────────────
TEST_F(E2ETest, FullStack_SealUnsealViaDBus) {
  std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"

  auto sealed = client.seal_data(plaintext);
  ASSERT_FALSE(sealed.empty()) << "seal_data via D-Bus failed";

  // 密文不等于明文
  EXPECT_NE(sealed, plaintext);

  auto unsealed = client.unseal_data(sealed);
  EXPECT_EQ(unsealed, plaintext);
}

TEST_F(E2ETest, FullStack_SealUnseal_LargeData) {
  std::vector<uint8_t> data(8192, 0x42);
  auto sealed = client.seal_data(data);
  ASSERT_FALSE(sealed.empty());
  auto unsealed = client.unseal_data(sealed);
  EXPECT_EQ(unsealed, data);
}

// ── 凭据生命周期通过 D-Bus ──────────────────────────────────
TEST_F(E2ETest, FullStack_CredentialLifecycle) {
  // 构造凭据
  CredentialSerializer::Credential cred;
  cred.credential_id = {0xAA, 0xBB, 0xCC, 0xDD};
  cred.private_key.resize(32, 0x11);
  cred.app_id.resize(32, 0x22);
  cred.user_id = {0x01, 0x02, 0x03};
  cred.user_name = "e2e_user";
  cred.rp_id = "e2e.example.com";
  cred.counter = 42;

  auto serialized = CredentialSerializer::serialize({cred});

  // 通过 D-Bus 加载到 FIDO2Device
  EXPECT_TRUE(client.load_credentials(serialized));

  // 通过 D-Bus 获取凭据
  auto got = client.get_credentials();
  auto creds = CredentialSerializer::deserialize(got);
  ASSERT_EQ(creds.size(), 1u);
  EXPECT_EQ(creds[0].credential_id, cred.credential_id);
  EXPECT_EQ(creds[0].rp_id, cred.rp_id);
  EXPECT_EQ(creds[0].counter, cred.counter);
}

// ── CredentialsChanged 信号通过 D-Bus ────────────────────────
TEST_F(E2ETest, FullStack_CredentialsChangedSignal) {
  std::atomic<bool> signal_received{false};
  client.set_credentials_changed_callback([&]() { signal_received = true; });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  server.notify_credentials_changed();

  // pump client 事件循环以接收信号
  for (int i = 0; i < 50 && !signal_received; ++i) {
    client.run();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  EXPECT_TRUE(signal_received);
}

// ── Ping 通过全栈 ───────────────────────────────────────────
TEST_F(E2ETest, FullStack_Ping) {
  EXPECT_TRUE(client.ping());
  EXPECT_TRUE(client.is_service_ready());
}
