#include <cbor.h>
#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <flat_map>
#include <string>
#include <vector>

#include "cbor_helper.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;
#include "fido2_device.h"  // for AAGUID

using namespace howdy;

// ── CborValue type system ────────────────────────────────────
TEST(CborValue, DefaultIsNull) {
  CborValue v;
  EXPECT_TRUE(v.is_null());
  EXPECT_FALSE(v.is_bool());
  EXPECT_FALSE(v.is_int());
  EXPECT_FALSE(v.is_string());
}

TEST(CborValue, BoolType) {
  CborValue v(true);
  EXPECT_TRUE(v.is_bool());
  EXPECT_TRUE(v.as_bool());
}

TEST(CborValue, IntType) {
  CborValue v(42);
  EXPECT_TRUE(v.is_int());
  EXPECT_EQ(v.as_int(), 42);
}

TEST(CborValue, UintType) {
  CborValue v(uint64_t{100});
  EXPECT_TRUE(v.is_uint());
  EXPECT_EQ(v.as_uint(), 100u);
}

TEST(CborValue, StringType) {
  CborValue v("hello");
  EXPECT_TRUE(v.is_string());
  EXPECT_EQ(v.as_string(), "hello");
}

TEST(CborValue, BytesType) {
  CborValue::Bytes b = {0x01, 0x02, 0x03};
  CborValue v(b);
  EXPECT_TRUE(v.is_bytes());
  EXPECT_EQ(v.as_bytes(), b);
}

TEST(CborValue, ArrayType) {
  CborValue::Array arr = {CborValue(1), CborValue("two")};
  CborValue v(arr);
  EXPECT_TRUE(v.is_array());
  ASSERT_EQ(v.as_array().size(), 2u);
  EXPECT_TRUE(v.as_array()[0].is_int());
  EXPECT_TRUE(v.as_array()[1].is_string());
}

TEST(CborValue, MapType) {
  CborValue::Map m;
  m[1] = CborValue("one");
  m[2] = CborValue(true);
  CborValue v(m);
  EXPECT_TRUE(v.is_map());
  EXPECT_EQ(v.as_map().size(), 2u);
}

TEST(CborValue, StringMapType) {
  CborValue::StringMap sm;
  sm["key"] = CborValue(42);
  CborValue v(sm);
  EXPECT_TRUE(v.is_string_map());
  EXPECT_EQ(v.as_string_map().at("key").as_int(), 42);
}

// ── CborEncoder::encode_get_info ─────────────────────────────
TEST(CborEncoder, EncodeGetInfo_ValidCBOR) {
  std::vector<std::string> versions = {"FIDO_2_0", "U2F_V2"};
  std::vector<std::string> extensions = {"credProtect"};
  std::vector<uint8_t> aaguid(AAGUID.begin(), AAGUID.end());
  std::flat_map<std::string, uint8_t> options = {{"rk", 1}, {"up", 1}};
  std::vector<int> pin_protocols = {1};

  auto encoded = CborEncoder::encode_get_info(versions, extensions, aaguid,
                                              options, 1200, pin_protocols);
  ASSERT_FALSE(encoded.empty());

  // 解析验证是合法 CBOR
  cbor_load_result result{};
  cbor_item_t* item = cbor_load(encoded.data(), encoded.size(), &result);
  ASSERT_NE(item, nullptr);
  EXPECT_TRUE(cbor_isa_map(item));
  cbor_decref(&item);
}

TEST(CborEncoder, EncodeGetInfo_ContainsVersions) {
  std::vector<std::string> versions = {"FIDO_2_0"};
  std::flat_map<std::string, uint8_t> options;
  std::vector<uint8_t> aaguid(16, 0);
  std::vector<int> pin_protocols;

  auto encoded = CborEncoder::encode_get_info(versions, {}, aaguid, options,
                                              1200, pin_protocols);
  ASSERT_FALSE(encoded.empty());

  cbor_load_result result{};
  cbor_item_t* root = cbor_load(encoded.data(), encoded.size(), &result);
  ASSERT_NE(root, nullptr);
  ASSERT_TRUE(cbor_isa_map(root));

  // Key 1 (versions) 应该包含 "FIDO_2_0"
  size_t map_size = cbor_map_size(root);
  bool found_versions = false;
  auto* pairs = cbor_map_handle(root);
  for (size_t i = 0; i < map_size; ++i) {
    if (cbor_isa_uint(pairs[i].key) && cbor_get_uint8(pairs[i].key) == 1) {
      ASSERT_TRUE(cbor_isa_array(pairs[i].value));
      size_t arr_size = cbor_array_size(pairs[i].value);
      ASSERT_GE(arr_size, 1u);
      auto* elem = cbor_array_get(pairs[i].value, 0);
      ASSERT_TRUE(cbor_isa_string(elem));
      std::string ver(reinterpret_cast<const char*>(cbor_string_handle(elem)),
                      cbor_string_length(elem));
      EXPECT_EQ(ver, "FIDO_2_0");
      cbor_decref(&elem);
      found_versions = true;
      break;
    }
  }
  EXPECT_TRUE(found_versions);
  cbor_decref(&root);
}

TEST(CborEncoder, EncodeGetInfo_ContainsAAGUID) {
  std::vector<std::string> versions = {"FIDO_2_0"};
  std::flat_map<std::string, uint8_t> options;
  std::vector<uint8_t> aaguid(AAGUID.begin(), AAGUID.end());
  std::vector<int> pin_protocols;

  auto encoded = CborEncoder::encode_get_info(versions, {}, aaguid, options,
                                              1200, pin_protocols);

  cbor_load_result result{};
  cbor_item_t* root = cbor_load(encoded.data(), encoded.size(), &result);
  ASSERT_NE(root, nullptr);

  // Key 3 (aaguid) 应该是 16 字节的 AAGUID
  auto* pairs = cbor_map_handle(root);
  size_t map_size = cbor_map_size(root);
  bool found = false;
  for (size_t i = 0; i < map_size; ++i) {
    if (cbor_isa_uint(pairs[i].key) && cbor_get_uint8(pairs[i].key) == 3) {
      ASSERT_TRUE(cbor_isa_bytestring(pairs[i].value));
      EXPECT_EQ(cbor_bytestring_length(pairs[i].value), 16u);
      auto* p = cbor_bytestring_handle(pairs[i].value);
      std::vector<uint8_t> got(p, p + 16);
      EXPECT_EQ(got, aaguid);
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found);
  cbor_decref(&root);
}

// ── CborEncoder::encode_make_credential_response ─────────────
TEST(CborEncoder, EncodeMakeCredentialResponse_ValidCBOR) {
  std::vector<uint8_t> auth_data(37, 0x01);
  std::vector<uint8_t> sig = {0x30, 0x44};   // mock DER sig
  std::vector<uint8_t> cert = {0x30, 0x82};  // mock DER cert

  auto encoded = CborEncoder::encode_make_credential_response(
      "packed", auth_data, sig, cert);
  ASSERT_FALSE(encoded.empty());

  cbor_load_result result{};
  cbor_item_t* root = cbor_load(encoded.data(), encoded.size(), &result);
  ASSERT_NE(root, nullptr);
  EXPECT_TRUE(cbor_isa_map(root));
  cbor_decref(&root);
}

// ── CborEncoder::encode_get_assertion_response ───────────────
TEST(CborEncoder, EncodeGetAssertionResponse_ValidCBOR) {
  std::vector<uint8_t> cred_id = {0x01, 0x02, 0x03};
  std::vector<uint8_t> auth_data(37, 0x02);
  std::vector<uint8_t> sig = {0x30, 0x44};
  std::vector<uint8_t> user_id = {0x10, 0x20};

  auto encoded = CborEncoder::encode_get_assertion_response(
      cred_id, auth_data, sig, user_id, "testuser");
  ASSERT_FALSE(encoded.empty());

  cbor_load_result result{};
  cbor_item_t* root = cbor_load(encoded.data(), encoded.size(), &result);
  ASSERT_NE(root, nullptr);
  EXPECT_TRUE(cbor_isa_map(root));
  cbor_decref(&root);
}

// ── CborEncoder::encode_cose_key ─────────────────────────────
TEST(CborEncoder, EncodeCoseKey_ES256) {
  // 65-byte uncompressed P-256 public key (04 || x || y)
  std::vector<uint8_t> pub_key(65, 0);
  pub_key[0] = 0x04;
  for (int i = 1; i <= 32; ++i) pub_key[i] = static_cast<uint8_t>(i);
  for (int i = 33; i <= 64; ++i) pub_key[i] = static_cast<uint8_t>(i);

  auto encoded = CborEncoder::encode_cose_key(pub_key);
  ASSERT_FALSE(encoded.empty());

  cbor_load_result result{};
  cbor_item_t* root = cbor_load(encoded.data(), encoded.size(), &result);
  ASSERT_NE(root, nullptr);
  ASSERT_TRUE(cbor_isa_map(root));

  // 验证 COSE key 结构：kty(1)=2(EC2), alg(3)=-7(ES256), crv(-1)=1(P-256)
  auto* pairs = cbor_map_handle(root);
  size_t size = cbor_map_size(root);
  EXPECT_GE(size, 5u);  // kty, alg, crv, x, y

  cbor_decref(&root);
}

// ── CborDecoder::parse_make_credential ───────────────────────
TEST(CborDecoder, ParseMakeCredential_InvalidData) {
  auto req = CborDecoder::parse_make_credential({});
  EXPECT_FALSE(req.valid);
}

TEST(CborDecoder, ParseMakeCredential_GarbageData) {
  std::vector<uint8_t> garbage = {0xFF, 0xFF, 0xFF, 0xFF};
  auto req = CborDecoder::parse_make_credential(garbage);
  EXPECT_FALSE(req.valid);
}

// ── CborDecoder::parse_get_assertion ─────────────────────────
TEST(CborDecoder, ParseGetAssertion_InvalidData) {
  auto req = CborDecoder::parse_get_assertion({});
  EXPECT_FALSE(req.valid);
}

TEST(CborDecoder, ParseGetAssertion_GarbageData) {
  std::vector<uint8_t> garbage = {0xFE, 0xED, 0xFA, 0xCE};
  auto req = CborDecoder::parse_get_assertion(garbage);
  EXPECT_FALSE(req.valid);
}

// ── Unsigned Integer Encoding Tests ──────────────────────────
TEST(CborEncoder, GetInfo_MaxMsgSize_MinimalEncoding) {
  // 测试 maxMsgSize 使用最小字节数编码
  std::vector<std::string> versions = {"FIDO_2_0"};
  std::vector<uint8_t> aaguid(16, 0);
  std::flat_map<std::string, uint8_t> options = {{"rk", true}};

  // 测试各种 maxMsgSize 值
  struct TestCase {
    uint32_t max_msg_size;
    const char* description;
  };

  std::vector<TestCase> cases = {
      {23, "fits_in_tiny_int"},    // <= 23: 直接编码
      {100, "uint8_range"},        // <= 0xFF: 1字节
      {255, "max_uint8"},          // uint8最大值
      {256, "min_uint16"},         // 需要2字节
      {2048, "typical_value"},     // 常用值
      {65535, "max_uint16"},       // uint16最大值
      {65536, "min_uint32"},       // 需要4字节
      {0xFFFFFFFF, "max_uint32"},  // uint32最大值
  };

  for (const auto& tc : cases) {
    SCOPED_TRACE(std::string("maxMsgSize=") + std::to_string(tc.max_msg_size) +
                 " (" + tc.description + ")");

    auto encoded = CborEncoder::encode_get_info(versions, {}, aaguid, options,
                                                tc.max_msg_size, {}, 0, 0);

    ASSERT_FALSE(encoded.empty());

    // 解析CBOR验证
    struct cbor_load_result result;
    cbor_item_t* item = cbor_load(encoded.data(), encoded.size(), &result);
    ASSERT_NE(item, nullptr);
    ASSERT_TRUE(cbor_isa_map(item));

    // 查找键5 (maxMsgSize)
    size_t map_size = cbor_map_size(item);
    struct cbor_pair* pairs = cbor_map_handle(item);
    bool found = false;

    for (size_t i = 0; i < map_size; i++) {
      if (cbor_isa_uint(pairs[i].key) && cbor_get_int(pairs[i].key) == 5) {
        found = true;
        cbor_item_t* value = pairs[i].value;
        ASSERT_TRUE(cbor_isa_uint(value));
        EXPECT_EQ(cbor_get_int(value), tc.max_msg_size);

        // 验证使用了最小字节数编码
        size_t value_size = cbor_serialized_size(value);
        if (tc.max_msg_size <= 23) {
          EXPECT_EQ(value_size, 1u) << "应使用tiny编码(1字节)";
        } else if (tc.max_msg_size <= 0xFF) {
          EXPECT_EQ(value_size, 2u) << "应使用uint8编码(2字节)";
        } else if (tc.max_msg_size <= 0xFFFF) {
          EXPECT_EQ(value_size, 3u) << "应使用uint16编码(3字节)";
        } else {
          EXPECT_EQ(value_size, 5u) << "应使用uint32编码(5字节)";
        }
        break;
      }
    }

    EXPECT_TRUE(found) << "未找到键5 (maxMsgSize)";
    cbor_decref(&item);
  }
}

TEST(CborEncoder, GetInfo_MaxCredentialIdLength_MinimalEncoding) {
  // 测试 maxCredentialIdLength 使用最小字节数编码
  std::vector<std::string> versions = {"FIDO_2_0"};
  std::vector<uint8_t> aaguid(16, 0);
  std::flat_map<std::string, uint8_t> options = {{"rk", true}};

  struct TestCase {
    int max_cred_id_length;
    const char* description;
  };

  std::vector<TestCase> cases = {
      {16, "small_value"},   {64, "medium_value"}, {128, "typical_value"},
      {255, "max_uint8"},    {256, "min_uint16"},  {1024, "large_value"},
      {65535, "max_uint16"},
  };

  for (const auto& tc : cases) {
    SCOPED_TRACE(std::string("maxCredentialIdLength=") +
                 std::to_string(tc.max_cred_id_length) + " (" + tc.description +
                 ")");

    auto encoded = CborEncoder::encode_get_info(
        versions, {}, aaguid, options, 2048, {}, 0, tc.max_cred_id_length);

    ASSERT_FALSE(encoded.empty());

    // 解析CBOR验证
    struct cbor_load_result result;
    cbor_item_t* item = cbor_load(encoded.data(), encoded.size(), &result);
    ASSERT_NE(item, nullptr);
    ASSERT_TRUE(cbor_isa_map(item));

    // 查找键8 (maxCredentialIdLength)
    size_t map_size = cbor_map_size(item);
    struct cbor_pair* pairs = cbor_map_handle(item);
    bool found = false;

    for (size_t i = 0; i < map_size; i++) {
      if (cbor_isa_uint(pairs[i].key) && cbor_get_int(pairs[i].key) == 8) {
        found = true;
        cbor_item_t* value = pairs[i].value;
        ASSERT_TRUE(cbor_isa_uint(value));
        EXPECT_EQ(cbor_get_int(value), tc.max_cred_id_length);

        // 验证使用了最小字节数编码
        size_t value_size = cbor_serialized_size(value);
        if (tc.max_cred_id_length <= 23) {
          EXPECT_EQ(value_size, 1u) << "应使用tiny编码(1字节)";
        } else if (tc.max_cred_id_length <= 0xFF) {
          EXPECT_EQ(value_size, 2u) << "应使用uint8编码(2字节)";
        } else {
          EXPECT_EQ(value_size, 3u) << "应使用uint16编码(3字节)";
        }
        break;
      }
    }

    EXPECT_TRUE(found) << "未找到键8 (maxCredentialIdLength)";
    cbor_decref(&item);
  }
}

TEST(CborEncoder, GetInfo_IntegerEncodingConsistency) {
  // 验证相同值在不同上下文中使用一致的编码
  std::vector<std::string> versions = {"FIDO_2_0"};
  std::vector<uint8_t> aaguid(16, 0);
  std::flat_map<std::string, uint8_t> options = {{"rk", true}};

  // 使用相同的值 (128) 作为两个参数
  const uint32_t test_value = 128;
  auto encoded =
      CborEncoder::encode_get_info(versions, {}, aaguid, options,
                                   test_value,  // maxMsgSize
                                   {}, 0,
                                   test_value  // maxCredentialIdLength
      );

  ASSERT_FALSE(encoded.empty());

  // 解析并验证两个值都使用相同的编码大小
  struct cbor_load_result result;
  cbor_item_t* item = cbor_load(encoded.data(), encoded.size(), &result);
  ASSERT_NE(item, nullptr);

  size_t map_size = cbor_map_size(item);
  struct cbor_pair* pairs = cbor_map_handle(item);

  size_t size_key5 = 0, size_key8 = 0;

  for (size_t i = 0; i < map_size; i++) {
    if (!cbor_isa_uint(pairs[i].key)) continue;
    int key = cbor_get_int(pairs[i].key);

    if (key == 5) {  // maxMsgSize
      size_key5 = cbor_serialized_size(pairs[i].value);
      EXPECT_EQ(cbor_get_int(pairs[i].value), test_value);
    } else if (key == 8) {  // maxCredentialIdLength
      size_key8 = cbor_serialized_size(pairs[i].value);
      EXPECT_EQ(cbor_get_int(pairs[i].value), test_value);
    }
  }

  // 相同的值应该使用相同的编码大小
  EXPECT_GT(size_key5, 0u);
  EXPECT_EQ(size_key5, size_key8) << "相同值应使用一致的编码";

  cbor_decref(&item);
}
