#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <string>
#include <vector>

#include "tpm_storage.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

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

// ── Counter 编码测试 ──────────────────────────────────────
TEST(CredentialSerializer, CounterEncodingConsistency) {
  // 验证 counter 使用固定4字节编码（大端序）
  // 不同的 counter 值应该总是占用相同的空间
  std::vector<Credential> test_cases;
  test_cases.push_back(make_cred("c1", 0));           // 最小值
  test_cases.push_back(make_cred("c2", 1));           // 单字节范围
  test_cases.push_back(make_cred("c3", 255));         // 单字节最大值
  test_cases.push_back(make_cred("c4", 256));         // 需要两字节
  test_cases.push_back(make_cred("c5", 65535));       // 双字节最大值
  test_cases.push_back(make_cred("c6", 65536));       // 需要三字节
  test_cases.push_back(make_cred("c7", 16777215));    // 三字节最大值
  test_cases.push_back(make_cred("c8", 0xFFFFFFFF));  // uint32最大值

  // 序列化每个凭据并验证大小一致性
  std::vector<size_t> sizes;
  for (const auto& c : test_cases) {
    auto data = CredentialSerializer::serialize({c});
    sizes.push_back(data.size());

    // 验证反序列化正确
    auto creds = CredentialSerializer::deserialize(data);
    ASSERT_EQ(creds.size(), 1u);
    EXPECT_EQ(creds[0].counter, c.counter);
  }

  // 所有序列化数据应该大小相同（因为只有counter不同）
  for (size_t i = 1; i < sizes.size(); ++i) {
    EXPECT_EQ(sizes[i], sizes[0])
        << "Counter值不同导致序列化大小不同: " << test_cases[i].counter;
  }
}

TEST(CredentialSerializer, CounterBoundaryValues) {
  // 测试counter的边界值
  struct TestCase {
    uint32_t counter;
    const char* description;
  };

  std::vector<TestCase> cases = {
      {0, "zero"},
      {1, "one"},
      {127, "max_positive_int7"},
      {128, "min_negative_int7"},
      {255, "max_uint8"},
      {256, "min_uint16"},
      {32767, "max_int15"},
      {32768, "min_negative_int15"},
      {65535, "max_uint16"},
      {65536, "min_uint24"},
      {2147483647, "max_int31"},
      {2147483648u, "min_negative_int31"},
      {0xFFFFFFFF, "max_uint32"},
  };

  for (const auto& tc : cases) {
    SCOPED_TRACE(std::string("counter=") + std::to_string(tc.counter) + " (" +
                 tc.description + ")");
    auto c = make_cred("test", tc.counter);
    auto data = CredentialSerializer::serialize({c});
    auto creds = CredentialSerializer::deserialize(data);
    ASSERT_EQ(creds.size(), 1u);
    EXPECT_EQ(creds[0].counter, tc.counter);
  }
}

// ── 返回值测试 ────────────────────────────────────────────
TEST(CredentialSerializer, SerializeReturnsNonEmpty) {
  auto c = make_cred("test", 1);
  auto data = CredentialSerializer::serialize({c});
  EXPECT_FALSE(data.empty());
  EXPECT_GT(data.size(), 0u);
}

TEST(CredentialSerializer, SerializeEmptyListReturnsValidData) {
  auto data = CredentialSerializer::serialize({});
  // 空列表应该返回包含版本号和计数的最小数据
  EXPECT_FALSE(data.empty());
  EXPECT_GE(data.size(), 5u);  // 1字节版本 + 4字节计数
}

TEST(CredentialSerializer, DeserializeEmptyReturnsEmpty) {
  std::vector<uint8_t> empty;
  auto creds = CredentialSerializer::deserialize(empty);
  EXPECT_TRUE(creds.empty());
  EXPECT_EQ(creds.size(), 0u);
}

TEST(CredentialSerializer, DeserializeInvalidReturnsEmpty) {
  // 各种无效输入都应该返回空列表
  std::vector<std::vector<uint8_t>> invalid_inputs = {
      {},                              // 空数据
      {0x01},                          // 只有版本号
      {0x01, 0x00, 0x00},              // 不完整的计数
      {0xFF, 0x00, 0x00, 0x00, 0x00},  // 错误的版本号
      {0x01, 0x00, 0x00, 0x00, 0x01},  // 计数为1但没有数据
      {0xDE, 0xAD, 0xBE, 0xEF},        // 纯垃圾数据
  };

  for (size_t i = 0; i < invalid_inputs.size(); ++i) {
    SCOPED_TRACE("invalid_input_case_" + std::to_string(i));
    auto creds = CredentialSerializer::deserialize(invalid_inputs[i]);
    EXPECT_TRUE(creds.empty());
  }
}

TEST(CredentialSerializer, SerializeThenDeserializeReturnsOriginal) {
  // 测试各种凭据配置的往返
  std::vector<Credential> test_cases;

  // 空凭据
  test_cases.push_back(Credential{});

  // 最小凭据
  Credential minimal;
  minimal.credential_id = {0x01};
  minimal.counter = 0;
  test_cases.push_back(minimal);

  // 正常凭据
  test_cases.push_back(make_cred("normal", 42));

  // 大counter值
  test_cases.push_back(make_cred("bigcounter", 0xFFFFFFF0));

  for (size_t i = 0; i < test_cases.size(); ++i) {
    SCOPED_TRACE("test_case_" + std::to_string(i));
    auto data = CredentialSerializer::serialize({test_cases[i]});
    EXPECT_FALSE(data.empty());

    auto creds = CredentialSerializer::deserialize(data);
    ASSERT_EQ(creds.size(), 1u);
    assert_cred_eq(creds[0], test_cases[i]);
  }
}

TEST(CredentialSerializer, PartialDeserializeReturnsPartialResults) {
  // 如果数据在中途损坏，应该返回已成功解析的凭据
  std::vector<Credential> orig = {
      make_cred("first", 1),
      make_cred("second", 2),
      make_cred("third", 3),
  };

  auto full_data = CredentialSerializer::serialize(orig);

  // 找到第二个凭据开始的位置（跳过版本、计数和第一个凭据）
  // 这需要计算第一个凭据的大小
  auto first_only = CredentialSerializer::serialize({orig[0]});
  size_t first_cred_size = first_only.size() - 5;  // 减去版本和计数

  // 在第二个凭据中间截断
  size_t truncate_pos =
      5 + first_cred_size + 10;  // 版本+计数+第一个凭据+部分第二个
  if (truncate_pos < full_data.size()) {
    auto truncated = std::vector<uint8_t>(full_data.begin(),
                                          full_data.begin() + truncate_pos);

    auto creds = CredentialSerializer::deserialize(truncated);
    // 应该至少得到第一个凭据
    ASSERT_GE(creds.size(), 1u);
    assert_cred_eq(creds[0], orig[0]);
  }
}

TEST(CredentialSerializer, MaxSizeFields) {
  // 测试最大尺寸字段（uint16_t最大值 = 65535）
  Credential c;
  c.credential_id = std::vector<uint8_t>(65535, 0xAA);
  c.private_key = std::vector<uint8_t>(65535, 0xBB);
  c.user_name = std::string(65535, 'X');
  c.counter = 999;

  auto data = CredentialSerializer::serialize({c});
  EXPECT_FALSE(data.empty());

  auto creds = CredentialSerializer::deserialize(data);
  ASSERT_EQ(creds.size(), 1u);
  EXPECT_EQ(creds[0].credential_id.size(), 65535u);
  EXPECT_EQ(creds[0].private_key.size(), 65535u);
  EXPECT_EQ(creds[0].user_name.size(), 65535u);
  EXPECT_EQ(creds[0].counter, 999u);
}

TEST(CredentialSerializer, MultipleCredentialsReturnsCorrectCount) {
  for (size_t count = 0; count <= 10; ++count) {
    SCOPED_TRACE("credential_count=" + std::to_string(count));

    std::vector<Credential> creds;
    for (size_t i = 0; i < count; ++i) {
      creds.push_back(make_cred("c" + std::to_string(i), i));
    }

    auto data = CredentialSerializer::serialize(creds);
    auto deserialized = CredentialSerializer::deserialize(data);

    EXPECT_EQ(deserialized.size(), count);
  }
}
