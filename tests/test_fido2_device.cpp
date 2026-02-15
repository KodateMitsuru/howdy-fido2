#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "crypto.h"

#define private public
#define protected public
#include "fido2_device.h"
#undef private
#undef protected

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

// ── GetAssertion Error Handling Tests ────────────────────────
// 测试修复：GetAssertion应返回CTAP2_ERR_NO_CREDENTIALS而不是空响应

class FIDO2DeviceErrorTest : public ::testing::Test {
 protected:
  FIDO2Device device;

  void SetUp() override {
    // 设置始终成功的auth handler
    device.set_auth_handler(
        [](const std::string&, const std::string&) -> bool { return true; });
  }
};

TEST_F(FIDO2DeviceErrorTest, GetAssertion_NoCredentials_ReturnsErrorCode) {
  // 确保设备没有凭据
  device.load_credentials_from_data(CredentialSerializer::serialize({}));

  // 构造一个有效的GetAssertion CBOR请求
  // map(2) { 1: "example.com", 2: clientDataHash(32 bytes) }
  std::vector<uint8_t> cbor_request;
  cbor_request.push_back(0xA2);  // map(2)

  // 键1: rpId
  cbor_request.push_back(0x01);
  cbor_request.push_back(0x6B);  // text(11) "example.com"
  for (char c : std::string("example.com")) cbor_request.push_back(c);

  // 键2: clientDataHash
  cbor_request.push_back(0x02);
  cbor_request.push_back(0x58);  // bytes(32)
  cbor_request.push_back(32);
  for (int i = 0; i < 32; i++) cbor_request.push_back(0xAA);

  // 调用 handle_get_assertion
  auto response = device.handle_get_assertion(cbor_request);

  // 验证返回了错误码而不是空响应
  ASSERT_FALSE(response.empty()) << "GetAssertion应返回错误码，不是空响应";
  ASSERT_EQ(response.size(), 1u);

  // CTAP2_ERR_NO_CREDENTIALS = 0x2E
  constexpr uint8_t CTAP2_ERR_NO_CREDENTIALS = 0x2E;
  EXPECT_EQ(response[0], CTAP2_ERR_NO_CREDENTIALS)
      << "应返回CTAP2_ERR_NO_CREDENTIALS (0x2E)";
}

TEST_F(FIDO2DeviceErrorTest,
       GetAssertion_NoMatchingCredentials_ReturnsNoCredentials) {
  // 加载一个凭据，但RP ID不匹配
  CredentialSerializer::Credential cred;
  cred.credential_id = {0x01, 0x02, 0x03, 0x04};
  cred.private_key.resize(32, 0xAA);

  // 计算 "different.com" 的 SHA256 hash
  std::string different_rp = "different.com";
  std::vector<uint8_t> different_rp_bytes(different_rp.begin(),
                                          different_rp.end());
  cred.app_id = CryptoUtils::sha256(different_rp_bytes);

  cred.user_id = {0x10};
  cred.user_name = "test";
  cred.rp_id = "different.com";
  cred.counter = 1;

  device.load_credentials_from_data(CredentialSerializer::serialize({cred}));

  // 构造GetAssertion请求，请求 "example.com"（与存储的凭据不匹配）
  std::vector<uint8_t> cbor_request;
  cbor_request.push_back(0xA2);  // map(2)

  // 键1: rpId = "example.com"
  cbor_request.push_back(0x01);
  cbor_request.push_back(0x6B);  // text(11)
  for (char c : std::string("example.com")) cbor_request.push_back(c);

  // 键2: clientDataHash
  cbor_request.push_back(0x02);
  cbor_request.push_back(0x58);  // bytes(32)
  cbor_request.push_back(32);
  for (int i = 0; i < 32; i++) cbor_request.push_back(0xBB);

  auto response = device.handle_get_assertion(cbor_request);

  // 应该返回NO_CREDENTIALS因为RP ID不匹配
  ASSERT_FALSE(response.empty());
  ASSERT_EQ(response.size(), 1u);

  constexpr uint8_t CTAP2_ERR_NO_CREDENTIALS = 0x2E;
  EXPECT_EQ(response[0], CTAP2_ERR_NO_CREDENTIALS);
}

TEST_F(FIDO2DeviceErrorTest, GetAssertion_InvalidCBOR_ReturnsError) {
  // 测试无效的CBOR数据
  std::vector<uint8_t> invalid_cbor = {0xFF, 0xFF, 0xFF};

  auto response = device.handle_get_assertion(invalid_cbor);

  // 应该返回INVALID_CBOR错误
  ASSERT_FALSE(response.empty());
  ASSERT_EQ(response.size(), 1u);

  constexpr uint8_t CTAP2_ERR_INVALID_CBOR = 0x12;
  EXPECT_EQ(response[0], CTAP2_ERR_INVALID_CBOR);
}

TEST_F(FIDO2DeviceErrorTest, GetAssertion_EmptyData_ReturnsError) {
  // 测试空数据
  std::vector<uint8_t> empty;

  auto response = device.handle_get_assertion(empty);

  // 应该返回错误码
  ASSERT_FALSE(response.empty());
  EXPECT_EQ(response.size(), 1u);
}

// ── 凭据变更回调测试 ──────────────────────────────────────────
TEST_F(FIDO2DeviceErrorTest,
       CredentialsChangedCallback_TriggeredByMakeCredential) {
  // 测试 handle_make_credential 会触发 credentials_changed 回调
  bool callback_fired = false;
  device.set_credentials_changed_callback([&]() { callback_fired = true; });

  // 构造一个有效的MakeCredential CBOR请求
  // map { 1: clientDataHash, 2: {id: "test.com"}, 3: {id: bytes, name: "user"}
  // }
  std::vector<uint8_t> cbor_request;
  cbor_request.push_back(0xA3);  // map(3)

  // 键1: clientDataHash (32 bytes)
  cbor_request.push_back(0x01);
  cbor_request.push_back(0x58);  // bytes(32)
  cbor_request.push_back(32);
  for (int i = 0; i < 32; i++) cbor_request.push_back(0xAA);

  // 键2: rp {id: "test.com"}
  cbor_request.push_back(0x02);
  cbor_request.push_back(0xA1);  // map(1)
  cbor_request.push_back(0x62);  // text(2) "id"
  cbor_request.push_back('i');
  cbor_request.push_back('d');
  cbor_request.push_back(0x68);  // text(8) "test.com"
  for (char c : std::string("test.com")) cbor_request.push_back(c);

  // 键3: user {id: bytes(4), name: "testuser"}
  cbor_request.push_back(0x03);
  cbor_request.push_back(0xA2);  // map(2)
  cbor_request.push_back(0x62);  // text(2) "id"
  cbor_request.push_back('i');
  cbor_request.push_back('d');
  cbor_request.push_back(0x44);  // bytes(4)
  cbor_request.push_back(0x01);
  cbor_request.push_back(0x02);
  cbor_request.push_back(0x03);
  cbor_request.push_back(0x04);
  cbor_request.push_back(0x64);  // text(4) "name"
  for (char c : std::string("name")) cbor_request.push_back(c);
  cbor_request.push_back(0x68);  // text(8) "testuser"
  for (char c : std::string("testuser")) cbor_request.push_back(c);

  // 调用 handle_make_credential
  auto response = device.handle_make_credential(cbor_request);

  // 验证回调被触发
  EXPECT_TRUE(callback_fired)
      << "MakeCredential应该触发credentials_changed回调";

  // 验证响应成功
  ASSERT_FALSE(response.empty());
  EXPECT_EQ(response[0], 0x00) << "应该返回CTAP2_OK";
}

TEST_F(FIDO2DeviceErrorTest, CredentialsChangedCallback_NotTriggeredByLoad) {
  // 测试 load_credentials_from_data 不触发回调（这是正确的设计）
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

  // load_credentials_from_data 不应该触发回调
  EXPECT_FALSE(callback_fired) << "load_credentials_from_data不应触发回调";
}
