#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "tpm_storage.h"

using namespace howdy;
using Credential = CredentialSerializer::Credential;

// ── helpers ──────────────────────────────────────────────────
static Credential make_cred(const std::string& tag, uint32_t counter = 0) {
  Credential c;
  c.credential_id = {tag.begin(), tag.end()};
  c.private_key.resize(32, static_cast<uint8_t>(tag[0]));
  c.app_id.resize(32, 0xAA);
  c.user_id = {0x01, 0x02, 0x03, 0x04};
  c.user_name = "user_" + tag;
  c.rp_id = "example.com";
  c.counter = counter;
  return c;
}

static void assert_cred_eq(const Credential& a, const Credential& b) {
  EXPECT_EQ(a.credential_id, b.credential_id);
  EXPECT_EQ(a.private_key, b.private_key);
  EXPECT_EQ(a.app_id, b.app_id);
  EXPECT_EQ(a.user_id, b.user_id);
  EXPECT_EQ(a.user_name, b.user_name);
  EXPECT_EQ(a.rp_id, b.rp_id);
  EXPECT_EQ(a.counter, b.counter);
}

// ── Tests ────────────────────────────────────────────────────
TEST(CredentialSerializer, EmptyRoundtrip) {
  auto data = CredentialSerializer::serialize({});
  auto creds = CredentialSerializer::deserialize(data);
  EXPECT_TRUE(creds.empty());
}

TEST(CredentialSerializer, SingleCredentialRoundtrip) {
  auto c = make_cred("A", 42);
  auto data = CredentialSerializer::serialize({c});
  auto creds = CredentialSerializer::deserialize(data);
  ASSERT_EQ(creds.size(), 1u);
  assert_cred_eq(creds[0], c);
}

TEST(CredentialSerializer, MultipleCredentials) {
  std::vector<Credential> orig = {
      make_cred("alpha", 0),
      make_cred("beta", 100),
      make_cred("gamma", 999999),
  };
  auto data = CredentialSerializer::serialize(orig);
  auto creds = CredentialSerializer::deserialize(data);
  ASSERT_EQ(creds.size(), 3u);
  for (size_t i = 0; i < 3; ++i) {
    SCOPED_TRACE("credential index " + std::to_string(i));
    assert_cred_eq(creds[i], orig[i]);
  }
}

TEST(CredentialSerializer, CorruptedData) {
  std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
  auto creds = CredentialSerializer::deserialize(garbage);
  EXPECT_TRUE(creds.empty());
}

TEST(CredentialSerializer, TruncatedData) {
  auto c = make_cred("trunc", 1);
  auto data = CredentialSerializer::serialize({c});
  ASSERT_GT(data.size(), 10u);
  // 截断到一半
  data.resize(data.size() / 2);
  auto creds = CredentialSerializer::deserialize(data);
  EXPECT_TRUE(creds.empty());
}

TEST(CredentialSerializer, WrongVersion) {
  auto c = make_cred("ver", 1);
  auto data = CredentialSerializer::serialize({c});
  ASSERT_FALSE(data.empty());
  // 第一字节是版本号，替换为非法值
  data[0] = 0xFF;
  auto creds = CredentialSerializer::deserialize(data);
  EXPECT_TRUE(creds.empty());
}

TEST(CredentialSerializer, LargeFields) {
  Credential c;
  c.credential_id.resize(1024, 0x42);
  c.private_key.resize(1024, 0x43);
  c.app_id.resize(32, 0x44);
  c.user_id.resize(256, 0x45);
  c.user_name = std::string(512, 'Z');
  c.rp_id = std::string(256, 'R');
  c.counter = 0xFFFFFFFF;

  auto data = CredentialSerializer::serialize({c});
  auto creds = CredentialSerializer::deserialize(data);
  ASSERT_EQ(creds.size(), 1u);
  assert_cred_eq(creds[0], c);
}

TEST(CredentialSerializer, SerializeDeterministic) {
  auto c = make_cred("det", 7);
  auto d1 = CredentialSerializer::serialize({c});
  auto d2 = CredentialSerializer::serialize({c});
  EXPECT_EQ(d1, d2);
}

TEST(CredentialSerializer, EmptyFields) {
  Credential c;
  // 所有字段为空
  c.counter = 0;
  auto data = CredentialSerializer::serialize({c});
  auto creds = CredentialSerializer::deserialize(data);
  ASSERT_EQ(creds.size(), 1u);
  assert_cred_eq(creds[0], c);
}
