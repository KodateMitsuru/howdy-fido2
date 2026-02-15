#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "fido2_device.h"
#include "tpm_storage.h"

using namespace howdy;

// ── AAGUID constant ──────────────────────────────────────────
TEST(FIDO2DeviceConst, AAGUID_Size) { EXPECT_EQ(AAGUID.size(), 16u); }

TEST(FIDO2DeviceConst, AAGUID_StartsWithHOWDY) {
  EXPECT_EQ(AAGUID[0], 'H');
  EXPECT_EQ(AAGUID[1], 'O');
  EXPECT_EQ(AAGUID[2], 'W');
  EXPECT_EQ(AAGUID[3], 'D');
  EXPECT_EQ(AAGUID[4], 'Y');
}

// ── Fixture: 需要 /dev/uhid (root) ──────────────────────────
class FIDO2DeviceTest : public ::testing::Test {
 protected:
  FIDO2Device device;
  bool started = false;

  void SetUp() override {
    // 设置始终成功的 auth handler
    device.set_auth_handler(
        [](const std::string&, const std::string&) -> bool { return true; });

    started = device.start();
    if (!started) {
      GTEST_SKIP() << "Cannot start FIDO2Device (need root for /dev/uhid)";
    }
  }

  void TearDown() override {
    if (started) {
      device.stop();
    }
  }
};

// ── Start / Stop 生命周期 ────────────────────────────────────
TEST_F(FIDO2DeviceTest, StartStop_Lifecycle) {
  EXPECT_TRUE(device.is_running());
  device.stop();
  started = false;
  EXPECT_FALSE(device.is_running());
}

// ── 凭据 roundtrip ──────────────────────────────────────────
TEST_F(FIDO2DeviceTest, CredentialsRoundtrip) {
  // 先获取空凭据
  auto empty_data = device.get_credentials_data();

  // 构造测试凭据并序列化
  CredentialSerializer::Credential cred;
  cred.credential_id = {0x01, 0x02, 0x03, 0x04};
  cred.private_key.resize(32, 0xAA);
  cred.app_id.resize(32, 0xBB);
  cred.user_id = {0x10, 0x20};
  cred.user_name = "test_user";
  cred.rp_id = "example.com";
  cred.counter = 5;

  auto serialized = CredentialSerializer::serialize({cred});
  ASSERT_TRUE(device.load_credentials_from_data(serialized));

  auto got = device.get_credentials_data();
  // 重新反序列化验证
  auto creds = CredentialSerializer::deserialize(got);
  ASSERT_EQ(creds.size(), 1u);
  EXPECT_EQ(creds[0].credential_id, cred.credential_id);
  EXPECT_EQ(creds[0].rp_id, cred.rp_id);
  EXPECT_EQ(creds[0].user_name, cred.user_name);
  EXPECT_EQ(creds[0].counter, cred.counter);
}

// ── 凭据变更回调 ─────────────────────────────────────────────
// load_credentials_from_data() 不触发 credentials_changed 回调
// （回调仅在 CTAP MakeCredential / U2F Register 等协议操作时触发）
// 此测试验证回调可以正确设置而不崩溃
TEST_F(FIDO2DeviceTest, CredentialsChangedCallback_SetNoThrow) {
  bool callback_fired = false;
  device.set_credentials_changed_callback([&]() { callback_fired = true; });

  CredentialSerializer::Credential cred;
  cred.credential_id = {0x05, 0x06};
  cred.private_key.resize(32, 0xCC);
  cred.app_id.resize(32, 0xDD);
  cred.user_id = {0x30};
  cred.user_name = "cb_user";
  cred.rp_id = "callback.test";
  cred.counter = 0;

  auto data = CredentialSerializer::serialize({cred});
  EXPECT_TRUE(device.load_credentials_from_data(data));
  // load_credentials_from_data 不触发回调 — 这是正确的设计
  EXPECT_FALSE(callback_fired);
}

// ── 空数据加载 ───────────────────────────────────────────────
TEST_F(FIDO2DeviceTest, EmptyCredentialsLoad) {
  auto empty_serialized = CredentialSerializer::serialize({});
  EXPECT_TRUE(device.load_credentials_from_data(empty_serialized));
  auto got = device.get_credentials_data();
  auto creds = CredentialSerializer::deserialize(got);
  EXPECT_TRUE(creds.empty());
}

// ── 多凭据加载 ───────────────────────────────────────────────
TEST_F(FIDO2DeviceTest, MultipleCredentials) {
  std::vector<CredentialSerializer::Credential> orig;
  for (int i = 0; i < 5; ++i) {
    CredentialSerializer::Credential c;
    c.credential_id = {static_cast<uint8_t>(i), 0x01, 0x02, 0x03};
    c.private_key.resize(32, static_cast<uint8_t>(i + 1));
    c.app_id.resize(32, 0xEE);
    c.user_id = {static_cast<uint8_t>(i)};
    c.user_name = "user" + std::to_string(i);
    c.rp_id = "site" + std::to_string(i) + ".com";
    c.counter = static_cast<uint32_t>(i * 10);
    orig.push_back(c);
  }

  auto data = CredentialSerializer::serialize(orig);
  ASSERT_TRUE(device.load_credentials_from_data(data));

  auto got = device.get_credentials_data();
  auto creds = CredentialSerializer::deserialize(got);
  EXPECT_EQ(creds.size(), 5u);
}
