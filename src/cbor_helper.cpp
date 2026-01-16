#include "cbor_helper.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstring>

namespace howdy {

// ============== CborEncoder 实现 ==============

std::vector<uint8_t> CborEncoder::encode(cbor_item_t* item) {
  if (!item) return {};

  size_t buffer_size = 1024;
  std::vector<uint8_t> buffer(buffer_size);
  size_t written = 0;

  // 尝试编码，如果缓冲区不够大则扩展
  while (true) {
    written = cbor_serialize(item, buffer.data(), buffer.size());
    if (written > 0 && written <= buffer.size()) {
      buffer.resize(written);
      break;
    }
    buffer_size *= 2;
    buffer.resize(buffer_size);
    if (buffer_size > 64 * 1024) {
      spdlog::error("CBOR: 编码缓冲区过大");
      return {};
    }
  }

  return buffer;
}

// 辅助函数：比较两个 CBOR 键的规范顺序
// 规则：先按长度排序，同长度按字节值排序
static bool cbor_key_less(const std::vector<uint8_t>& a,
                          const std::vector<uint8_t>& b) {
  if (a.size() != b.size()) return a.size() < b.size();
  return a < b;
}

// 辅助函数：编码单个键值对到缓冲区
static void encode_pair_to_buffer(std::vector<uint8_t>& buffer,
                                  cbor_item_t* key, cbor_item_t* value) {
  size_t key_size = cbor_serialized_size(key);
  size_t value_size = cbor_serialized_size(value);
  size_t old_size = buffer.size();
  buffer.resize(old_size + key_size + value_size);
  cbor_serialize(key, buffer.data() + old_size, key_size);
  cbor_serialize(value, buffer.data() + old_size + key_size, value_size);
}

// 辅助函数：按规范顺序编码 string-keyed map
static std::vector<uint8_t> encode_string_map_canonical(
    const std::map<std::string, cbor_item_t*>& items) {
  // 收集所有键值对的编码
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      encoded_pairs;

  for (const auto& [k, v] : items) {
    cbor_item_t* key = cbor_build_string(k.c_str());
    size_t key_size = cbor_serialized_size(key);
    std::vector<uint8_t> key_bytes(key_size);
    cbor_serialize(key, key_bytes.data(), key_size);
    cbor_decref(&key);

    size_t value_size = cbor_serialized_size(v);
    std::vector<uint8_t> value_bytes(value_size);
    cbor_serialize(v, value_bytes.data(), value_size);

    encoded_pairs.emplace_back(std::move(key_bytes), std::move(value_bytes));
  }

  // 按照键的规范顺序排序
  std::sort(encoded_pairs.begin(), encoded_pairs.end(),
            [](const auto& a, const auto& b) {
              return cbor_key_less(a.first, b.first);
            });

  // 构建结果
  std::vector<uint8_t> result;

  // Map header
  size_t count = encoded_pairs.size();
  if (count <= 23) {
    result.push_back(0xA0 | count);
  } else if (count <= 255) {
    result.push_back(0xB8);
    result.push_back(count);
  } else {
    result.push_back(0xB9);
    result.push_back((count >> 8) & 0xFF);
    result.push_back(count & 0xFF);
  }

  // 键值对
  for (const auto& [key_bytes, value_bytes] : encoded_pairs) {
    result.insert(result.end(), key_bytes.begin(), key_bytes.end());
    result.insert(result.end(), value_bytes.begin(), value_bytes.end());
  }

  return result;
}

std::vector<uint8_t> CborEncoder::encode_get_info(
    const std::vector<std::string>& versions,
    const std::vector<std::string>& extensions,
    const std::vector<uint8_t>& aaguid,
    const std::map<std::string, bool>& options, uint32_t max_msg_size,
    const std::vector<int>& pin_protocols, int max_cred_count,
    int max_cred_id_length) {
  // 手动构建规范 CBOR
  // CTAP2 GetInfo 响应使用整数键，必须按数值排序: 1, 2, 3, 4, 5, 6, 7, 8, 10
  std::vector<uint8_t> result;

  // 计算 map 大小
  int map_size = 4;  // versions, aaguid, maxMsgSize, algorithms 是必需的
  if (!extensions.empty()) map_size++;
  if (!options.empty()) map_size++;
  if (!pin_protocols.empty()) map_size++;
  if (max_cred_count > 0) map_size++;
  if (max_cred_id_length > 0) map_size++;

  // Map header
  if (map_size <= 23) {
    result.push_back(0xA0 | map_size);
  } else {
    result.push_back(0xB8);
    result.push_back(map_size);
  }

  // 1: versions (array of strings)
  result.push_back(0x01);  // key = 1
  cbor_item_t* versions_array = cbor_new_definite_array(versions.size());
  for (const auto& v : versions) {
    cbor_array_push(versions_array, cbor_move(cbor_build_string(v.c_str())));
  }
  auto versions_bytes = encode(versions_array);
  cbor_decref(&versions_array);
  result.insert(result.end(), versions_bytes.begin(), versions_bytes.end());

  // 2: extensions (if not empty)
  if (!extensions.empty()) {
    result.push_back(0x02);  // key = 2
    cbor_item_t* ext_array = cbor_new_definite_array(extensions.size());
    for (const auto& e : extensions) {
      cbor_array_push(ext_array, cbor_move(cbor_build_string(e.c_str())));
    }
    auto ext_bytes = encode(ext_array);
    cbor_decref(&ext_array);
    result.insert(result.end(), ext_bytes.begin(), ext_bytes.end());
  }

  // 3: aaguid (16 bytes)
  result.push_back(0x03);  // key = 3
  result.push_back(0x50);  // bytes(16)
  result.insert(result.end(), aaguid.begin(), aaguid.end());

  // 4: options (map of string -> bool) - 必须按键的规范顺序
  if (!options.empty()) {
    result.push_back(0x04);  // key = 4

    // 构建临时 map 用于排序
    std::map<std::string, cbor_item_t*> opts_items;
    for (const auto& [k, v] : options) {
      opts_items[k] = cbor_build_bool(v);
    }
    auto opts_bytes = encode_string_map_canonical(opts_items);
    for (auto& [k, v] : opts_items) {
      cbor_decref(&v);
    }
    result.insert(result.end(), opts_bytes.begin(), opts_bytes.end());
  }

  // 5: maxMsgSize
  result.push_back(0x05);  // key = 5
  result.push_back(0x19);  // uint16
  result.push_back((max_msg_size >> 8) & 0xFF);
  result.push_back(max_msg_size & 0xFF);

  // 6: pinUvAuthProtocols (if not empty)
  if (!pin_protocols.empty()) {
    result.push_back(0x06);                         // key = 6
    result.push_back(0x80 | pin_protocols.size());  // array(n)
    for (int p : pin_protocols) {
      result.push_back(p);  // small positive int
    }
  }

  // 7: maxCredentialCountInList
  if (max_cred_count > 0) {
    result.push_back(0x07);  // key = 7
    result.push_back(max_cred_count);
  }

  // 8: maxCredentialIdLength
  if (max_cred_id_length > 0) {
    result.push_back(0x08);  // key = 8
    if (max_cred_id_length <= 23) {
      result.push_back(max_cred_id_length);
    } else if (max_cred_id_length <= 255) {
      result.push_back(0x18);
      result.push_back(max_cred_id_length);
    }
  }

  // 0x0A (10): algorithms - 必须按键的规范顺序 ("alg" < "type" 因为长度 3 < 4)
  result.push_back(0x0A);  // key = 10
  result.push_back(0x81);  // array(1)
  result.push_back(0xA2);  // map(2)
  // "alg": -7 (3 bytes key)
  result.push_back(0x63);  // text(3)
  result.push_back('a');
  result.push_back('l');
  result.push_back('g');
  result.push_back(0x26);  // -7
  // "type": "public-key" (4 bytes key)
  result.push_back(0x64);  // text(4)
  result.push_back('t');
  result.push_back('y');
  result.push_back('p');
  result.push_back('e');
  result.push_back(0x6A);  // text(10)
  for (char c : std::string("public-key")) result.push_back(c);

  return result;
}

std::vector<uint8_t> CborEncoder::encode_cose_key(
    const std::vector<uint8_t>& public_key) {
  // 公钥格式: 04 || x(32) || y(32)
  if (public_key.size() != 65 || public_key[0] != 0x04) {
    spdlog::error("CBOR: 无效的公钥格式");
    return {};
  }

  // COSE_Key for ES256 (P-256)
  // 规范键顺序 (整数键): 1, 3, -1, -2, -3
  // 正整数先按值升序，负整数后按绝对值升序
  std::vector<uint8_t> result;

  result.push_back(0xA5);  // map(5)

  // 1: kty = 2 (EC2)
  result.push_back(0x01);  // key = 1
  result.push_back(0x02);  // value = 2

  // 3: alg = -7 (ES256)
  result.push_back(0x03);  // key = 3
  result.push_back(0x26);  // value = -7

  // -1: crv = 1 (P-256)
  result.push_back(0x20);  // key = -1
  result.push_back(0x01);  // value = 1

  // -2: x coordinate (32 bytes)
  result.push_back(0x21);  // key = -2
  result.push_back(0x58);  // bytes with 1-byte length
  result.push_back(0x20);  // length = 32
  result.insert(result.end(), public_key.begin() + 1, public_key.begin() + 33);

  // -3: y coordinate (32 bytes)
  result.push_back(0x22);  // key = -3
  result.push_back(0x58);  // bytes with 1-byte length
  result.push_back(0x20);  // length = 32
  result.insert(result.end(), public_key.begin() + 33, public_key.end());

  return result;
}

// 辅助函数：编码字节串
static void encode_bytes(std::vector<uint8_t>& result,
                         const std::vector<uint8_t>& data) {
  if (data.size() <= 23) {
    result.push_back(0x40 | data.size());
  } else if (data.size() <= 255) {
    result.push_back(0x58);
    result.push_back(data.size());
  } else {
    result.push_back(0x59);
    result.push_back((data.size() >> 8) & 0xFF);
    result.push_back(data.size() & 0xFF);
  }
  result.insert(result.end(), data.begin(), data.end());
}

// 辅助函数：编码文本串
static void encode_text(std::vector<uint8_t>& result, const std::string& text) {
  if (text.size() <= 23) {
    result.push_back(0x60 | text.size());
  } else if (text.size() <= 255) {
    result.push_back(0x78);
    result.push_back(text.size());
  } else {
    result.push_back(0x79);
    result.push_back((text.size() >> 8) & 0xFF);
    result.push_back(text.size() & 0xFF);
  }
  result.insert(result.end(), text.begin(), text.end());
}

std::vector<uint8_t> CborEncoder::encode_make_credential_response(
    const std::string& fmt, const std::vector<uint8_t>& auth_data,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& x5c_cert) {
  // MakeCredential 响应: map(3)
  // 整数键顺序: 1, 2, 3
  std::vector<uint8_t> result;

  result.push_back(0xA3);  // map(3)

  // 1: fmt (string)
  result.push_back(0x01);
  encode_text(result, fmt);

  // 2: authData (bytes)
  result.push_back(0x02);
  encode_bytes(result, auth_data);

  // 3: attStmt (map)
  result.push_back(0x03);

  if (x5c_cert.empty()) {
    // Self attestation: {"alg": -7, "sig": ...}
    // 键顺序: "alg"(3) < "sig"(3)，按字典序 "alg" < "sig"
    result.push_back(0xA2);  // map(2)

    // "alg": -7
    result.push_back(0x63);  // text(3)
    result.push_back('a');
    result.push_back('l');
    result.push_back('g');
    result.push_back(0x26);  // -7

    // "sig": signature
    result.push_back(0x63);  // text(3)
    result.push_back('s');
    result.push_back('i');
    result.push_back('g');
    encode_bytes(result, signature);
  } else {
    // Basic attestation: {"alg": -7, "sig": ..., "x5c": [...]}
    // 键顺序: "alg"(3) < "sig"(3) < "x5c"(3)
    result.push_back(0xA3);  // map(3)

    // "alg": -7
    result.push_back(0x63);  // text(3)
    result.push_back('a');
    result.push_back('l');
    result.push_back('g');
    result.push_back(0x26);  // -7

    // "sig": signature
    result.push_back(0x63);  // text(3)
    result.push_back('s');
    result.push_back('i');
    result.push_back('g');
    encode_bytes(result, signature);

    // "x5c": [cert]
    result.push_back(0x63);  // text(3)
    result.push_back('x');
    result.push_back('5');
    result.push_back('c');
    result.push_back(0x81);  // array(1)
    encode_bytes(result, x5c_cert);
  }

  return result;
}

std::vector<uint8_t> CborEncoder::encode_get_assertion_response(
    const std::vector<uint8_t>& credential_id,
    const std::vector<uint8_t>& auth_data,
    const std::vector<uint8_t>& signature, const std::vector<uint8_t>& user_id,
    const std::string& user_name) {
  // GetAssertion 响应: map(3 or 4)
  // 整数键顺序: 1, 2, 3, 4
  std::vector<uint8_t> result;

  bool has_user = !user_id.empty();
  result.push_back(has_user ? 0xA4 : 0xA3);  // map(4) or map(3)

  // 1: credential
  result.push_back(0x01);
  // credential map: {"id": bytes, "type": "public-key"}
  // 键顺序: "id"(2) < "type"(4)
  result.push_back(0xA2);  // map(2)
  // "id"
  result.push_back(0x62);  // text(2)
  result.push_back('i');
  result.push_back('d');
  encode_bytes(result, credential_id);
  // "type"
  result.push_back(0x64);  // text(4)
  result.push_back('t');
  result.push_back('y');
  result.push_back('p');
  result.push_back('e');
  encode_text(result, "public-key");

  // 2: authData
  result.push_back(0x02);
  encode_bytes(result, auth_data);

  // 3: signature
  result.push_back(0x03);
  encode_bytes(result, signature);

  // 4: user (optional)
  if (has_user) {
    result.push_back(0x04);
    // user map: {"id": bytes} or {"id": bytes, "name": string}
    // 键顺序: "id"(2) < "name"(4)
    bool has_name = !user_name.empty();
    result.push_back(has_name ? 0xA2 : 0xA1);  // map(2) or map(1)

    // "id"
    result.push_back(0x62);  // text(2)
    result.push_back('i');
    result.push_back('d');
    encode_bytes(result, user_id);

    // "name" (if present)
    if (has_name) {
      result.push_back(0x64);  // text(4)
      result.push_back('n');
      result.push_back('a');
      result.push_back('m');
      result.push_back('e');
      encode_text(result, user_name);
    }
  }

  return result;
}

// ============== CborDecoder 实现 ==============

std::string CborDecoder::get_string(cbor_item_t* item) {
  if (!item || !cbor_isa_string(item)) return "";
  return std::string(reinterpret_cast<const char*>(cbor_string_handle(item)),
                     cbor_string_length(item));
}

std::vector<uint8_t> CborDecoder::get_bytes(cbor_item_t* item) {
  if (!item || !cbor_isa_bytestring(item)) return {};
  const uint8_t* data = cbor_bytestring_handle(item);
  size_t len = cbor_bytestring_length(item);
  return std::vector<uint8_t>(data, data + len);
}

int64_t CborDecoder::get_int(cbor_item_t* item) {
  if (!item) return 0;
  if (cbor_isa_uint(item)) {
    return static_cast<int64_t>(cbor_get_int(item));
  } else if (cbor_isa_negint(item)) {
    return -1 - static_cast<int64_t>(cbor_get_int(item));
  }
  return 0;
}

CborDecoder::MakeCredentialRequest CborDecoder::parse_make_credential(
    const std::vector<uint8_t>& data) {
  MakeCredentialRequest req;
  if (data.empty()) return req;

  struct cbor_load_result result;
  cbor_item_t* item = cbor_load(data.data(), data.size(), &result);

  if (result.error.code != CBOR_ERR_NONE || !item || !cbor_isa_map(item)) {
    if (item) cbor_decref(&item);
    spdlog::error("CBOR: 解析 MakeCredential 请求失败");
    return req;
  }

  size_t map_size = cbor_map_size(item);
  struct cbor_pair* pairs = cbor_map_handle(item);

  for (size_t i = 0; i < map_size; i++) {
    int key = static_cast<int>(cbor_get_int(pairs[i].key));
    cbor_item_t* value = pairs[i].value;

    switch (key) {
      case 1:  // clientDataHash (bytes)
        req.client_data_hash = get_bytes(value);
        break;

      case 2:  // rp (map)
        if (cbor_isa_map(value)) {
          size_t rp_size = cbor_map_size(value);
          struct cbor_pair* rp_pairs = cbor_map_handle(value);
          for (size_t j = 0; j < rp_size; j++) {
            std::string rp_key = get_string(rp_pairs[j].key);
            if (rp_key == "id") {
              req.rp_id = get_string(rp_pairs[j].value);
            } else if (rp_key == "name") {
              req.rp_name = get_string(rp_pairs[j].value);
            }
          }
        }
        break;

      case 3:  // user (map)
        if (cbor_isa_map(value)) {
          size_t user_size = cbor_map_size(value);
          struct cbor_pair* user_pairs = cbor_map_handle(value);
          for (size_t j = 0; j < user_size; j++) {
            std::string user_key = get_string(user_pairs[j].key);
            if (user_key == "id") {
              req.user_id = get_bytes(user_pairs[j].value);
            } else if (user_key == "name") {
              req.user_name = get_string(user_pairs[j].value);
            } else if (user_key == "displayName") {
              req.user_display_name = get_string(user_pairs[j].value);
            }
          }
        }
        break;

      case 4:  // pubKeyCredParams (array)
        if (cbor_isa_array(value)) {
          size_t arr_size = cbor_array_size(value);
          for (size_t j = 0; j < arr_size; j++) {
            cbor_item_t* param = cbor_array_get(value, j);
            if (cbor_isa_map(param)) {
              std::string type;
              int alg = 0;
              size_t param_size = cbor_map_size(param);
              struct cbor_pair* param_pairs = cbor_map_handle(param);
              for (size_t k = 0; k < param_size; k++) {
                std::string pk = get_string(param_pairs[k].key);
                if (pk == "type") {
                  type = get_string(param_pairs[k].value);
                } else if (pk == "alg") {
                  alg = static_cast<int>(get_int(param_pairs[k].value));
                }
              }
              if (!type.empty()) {
                req.pub_key_cred_params.emplace_back(type, alg);
              }
            }
          }
        }
        break;

      case 5:  // excludeList (array)
        if (cbor_isa_array(value)) {
          size_t arr_size = cbor_array_size(value);
          for (size_t j = 0; j < arr_size; j++) {
            cbor_item_t* cred = cbor_array_get(value, j);
            if (cbor_isa_map(cred)) {
              size_t cred_size = cbor_map_size(cred);
              struct cbor_pair* cred_pairs = cbor_map_handle(cred);
              for (size_t k = 0; k < cred_size; k++) {
                std::string ck = get_string(cred_pairs[k].key);
                if (ck == "id") {
                  req.exclude_list.push_back(get_bytes(cred_pairs[k].value));
                }
              }
            }
          }
        }
        break;

      case 6:  // extensions (map)
        if (cbor_isa_map(value)) {
          size_t ext_size = cbor_map_size(value);
          struct cbor_pair* ext_pairs = cbor_map_handle(value);
          for (size_t j = 0; j < ext_size; j++) {
            std::string ext_key = get_string(ext_pairs[j].key);
            if (cbor_isa_uint(ext_pairs[j].value)) {
              req.extensions[ext_key] =
                  static_cast<int>(cbor_get_int(ext_pairs[j].value));
            } else if (cbor_is_bool(ext_pairs[j].value)) {
              req.extensions[ext_key] =
                  cbor_get_bool(ext_pairs[j].value) ? 1 : 0;
            }
          }
          spdlog::debug("CBOR: 收到扩展请求: {}", [&req]() {
            std::string s;
            for (const auto& [k, v] : req.extensions) {
              s += k + "=" + std::to_string(v) + " ";
            }
            return s;
          }());
        }
        break;

      case 7:  // options (map)
        if (cbor_isa_map(value)) {
          size_t opt_size = cbor_map_size(value);
          struct cbor_pair* opt_pairs = cbor_map_handle(value);
          for (size_t j = 0; j < opt_size; j++) {
            std::string opt_key = get_string(opt_pairs[j].key);
            if (cbor_is_bool(opt_pairs[j].value)) {
              req.options[opt_key] = cbor_get_bool(opt_pairs[j].value);
            }
          }
        }
        break;
    }
  }

  req.valid = !req.client_data_hash.empty() && !req.rp_id.empty();
  cbor_decref(&item);

  spdlog::debug("CBOR: MakeCredential 解析完成 - rp_id={}, user={}", req.rp_id,
                req.user_name);

  return req;
}

CborDecoder::GetAssertionRequest CborDecoder::parse_get_assertion(
    const std::vector<uint8_t>& data) {
  GetAssertionRequest req;
  if (data.empty()) return req;

  struct cbor_load_result result;
  cbor_item_t* item = cbor_load(data.data(), data.size(), &result);

  if (result.error.code != CBOR_ERR_NONE || !item || !cbor_isa_map(item)) {
    if (item) cbor_decref(&item);
    spdlog::error("CBOR: 解析 GetAssertion 请求失败");
    return req;
  }

  size_t map_size = cbor_map_size(item);
  struct cbor_pair* pairs = cbor_map_handle(item);

  for (size_t i = 0; i < map_size; i++) {
    int key = static_cast<int>(cbor_get_int(pairs[i].key));
    cbor_item_t* value = pairs[i].value;

    switch (key) {
      case 1:  // rpId (string)
        req.rp_id = get_string(value);
        break;

      case 2:  // clientDataHash (bytes)
        req.client_data_hash = get_bytes(value);
        break;

      case 3:  // allowList (array)
        if (cbor_isa_array(value)) {
          size_t arr_size = cbor_array_size(value);
          for (size_t j = 0; j < arr_size; j++) {
            cbor_item_t* cred = cbor_array_get(value, j);
            if (cbor_isa_map(cred)) {
              size_t cred_size = cbor_map_size(cred);
              struct cbor_pair* cred_pairs = cbor_map_handle(cred);
              for (size_t k = 0; k < cred_size; k++) {
                std::string ck = get_string(cred_pairs[k].key);
                if (ck == "id") {
                  req.allow_list.push_back(get_bytes(cred_pairs[k].value));
                }
              }
            }
          }
        }
        break;

      case 5:  // options (map)
        if (cbor_isa_map(value)) {
          size_t opt_size = cbor_map_size(value);
          struct cbor_pair* opt_pairs = cbor_map_handle(value);
          for (size_t j = 0; j < opt_size; j++) {
            std::string opt_key = get_string(opt_pairs[j].key);
            if (cbor_is_bool(opt_pairs[j].value)) {
              req.options[opt_key] = cbor_get_bool(opt_pairs[j].value);
            }
          }
        }
        break;
    }
  }

  req.valid = !req.rp_id.empty() && !req.client_data_hash.empty();
  cbor_decref(&item);

  spdlog::debug("CBOR: GetAssertion 解析完成 - rp_id={}", req.rp_id);

  return req;
}

}  // namespace howdy
