#pragma once

#include <cbor.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace howdy {

// CBOR 值的简单包装
class CborValue {
 public:
  using Map = std::map<int, CborValue>;
  using StringMap = std::map<std::string, CborValue>;
  using Array = std::vector<CborValue>;
  using Bytes = std::vector<uint8_t>;
  using Value = std::variant<std::monostate, bool, int64_t, uint64_t,
                             std::string, Bytes, Array, Map, StringMap>;

  CborValue() = default;
  CborValue(bool v) : value_(v) {}
  CborValue(int v) : value_(static_cast<int64_t>(v)) {}
  CborValue(int64_t v) : value_(v) {}
  CborValue(uint64_t v) : value_(v) {}
  CborValue(const std::string& v) : value_(v) {}
  CborValue(const char* v) : value_(std::string(v)) {}
  CborValue(const Bytes& v) : value_(v) {}
  CborValue(const Array& v) : value_(v) {}
  CborValue(const Map& v) : value_(v) {}
  CborValue(const StringMap& v) : value_(v) {}

  bool is_null() const {
    return std::holds_alternative<std::monostate>(value_);
  }
  bool is_bool() const { return std::holds_alternative<bool>(value_); }
  bool is_int() const { return std::holds_alternative<int64_t>(value_); }
  bool is_uint() const { return std::holds_alternative<uint64_t>(value_); }
  bool is_string() const { return std::holds_alternative<std::string>(value_); }
  bool is_bytes() const { return std::holds_alternative<Bytes>(value_); }
  bool is_array() const { return std::holds_alternative<Array>(value_); }
  bool is_map() const { return std::holds_alternative<Map>(value_); }
  bool is_string_map() const {
    return std::holds_alternative<StringMap>(value_);
  }

  bool as_bool() const { return std::get<bool>(value_); }
  int64_t as_int() const { return std::get<int64_t>(value_); }
  uint64_t as_uint() const { return std::get<uint64_t>(value_); }
  const std::string& as_string() const { return std::get<std::string>(value_); }
  const Bytes& as_bytes() const { return std::get<Bytes>(value_); }
  const Array& as_array() const { return std::get<Array>(value_); }
  const Map& as_map() const { return std::get<Map>(value_); }
  const StringMap& as_string_map() const { return std::get<StringMap>(value_); }

 private:
  Value value_;
};

// CBOR 编码/解码助手
class CborEncoder {
 public:
  CborEncoder() = default;

  // 编码 GetInfo 响应
  static std::vector<uint8_t> encode_get_info(
      const std::vector<std::string>& versions,
      const std::vector<std::string>& extensions,
      const std::vector<uint8_t>& aaguid,
      const std::map<std::string, bool>& options, uint32_t max_msg_size,
      const std::vector<int>& pin_protocols, int max_cred_count = 0,
      int max_cred_id_length = 0);

  // 编码 MakeCredential 响应
  static std::vector<uint8_t> encode_make_credential_response(
      const std::string& fmt, const std::vector<uint8_t>& auth_data,
      const std::vector<uint8_t>& signature,
      const std::vector<uint8_t>& x5c_cert = {}  // 可选的证书链
  );

  // 编码 GetAssertion 响应
  static std::vector<uint8_t> encode_get_assertion_response(
      const std::vector<uint8_t>& credential_id,
      const std::vector<uint8_t>& auth_data,
      const std::vector<uint8_t>& signature,
      const std::vector<uint8_t>& user_id = {},
      const std::string& user_name = "");

  // 编码 COSE Key (ES256/P-256)
  static std::vector<uint8_t> encode_cose_key(
      const std::vector<uint8_t>& public_key);

  // 通用编码方法
  static std::vector<uint8_t> encode(cbor_item_t* item);

 private:
  // 辅助方法
  static cbor_item_t* create_sorted_map();
  static void add_to_map(cbor_item_t* map, int key, cbor_item_t* value);
  static void add_to_map(cbor_item_t* map, const std::string& key,
                         cbor_item_t* value);
};

// CBOR 解码助手
class CborDecoder {
 public:
  // 解析 MakeCredential 请求
  struct MakeCredentialRequest {
    std::vector<uint8_t> client_data_hash;
    std::string rp_id;
    std::string rp_name;
    std::vector<uint8_t> user_id;
    std::string user_name;
    std::string user_display_name;
    std::vector<std::pair<std::string, int>> pub_key_cred_params;  // type, alg
    std::vector<std::vector<uint8_t>> exclude_list;
    std::map<std::string, bool> options;
    std::map<std::string, int> extensions;  // 扩展参数 (如 credProtect)
    bool valid = false;
  };

  static MakeCredentialRequest parse_make_credential(
      const std::vector<uint8_t>& data);

  // 解析 GetAssertion 请求
  struct GetAssertionRequest {
    std::string rp_id;
    std::vector<uint8_t> client_data_hash;
    std::vector<std::vector<uint8_t>> allow_list;
    std::map<std::string, bool> options;
    bool valid = false;
  };

  static GetAssertionRequest parse_get_assertion(
      const std::vector<uint8_t>& data);

 private:
  static std::string get_string(cbor_item_t* item);
  static std::vector<uint8_t> get_bytes(cbor_item_t* item);
  static int64_t get_int(cbor_item_t* item);
};

}  // namespace howdy
