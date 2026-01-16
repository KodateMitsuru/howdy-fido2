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

// 辅助函数：构建按规范顺序排序的 string-keyed map
static cbor_item_t* build_sorted_string_map(
    std::vector<std::pair<std::string, cbor_item_t*>>& items) {
  // 按规范顺序排序
  std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
    if (a.first.size() != b.first.size())
      return a.first.size() < b.first.size();
    return a.first < b.first;
  });

  cbor_item_t* map = cbor_new_definite_map(items.size());
  for (auto& [key, value] : items) {
    bool ok =
        cbor_map_add(map, {.key = cbor_move(cbor_build_string(key.c_str())),
                           .value = cbor_move(value)});
    if (!ok) {
      spdlog::warn("CBOR: cbor_map_add 失败");
    }
  }
  return map;
}

std::vector<uint8_t> CborEncoder::encode_get_info(
    const std::vector<std::string>& versions,
    const std::vector<std::string>& extensions,
    const std::vector<uint8_t>& aaguid,
    const std::map<std::string, bool>& options, uint32_t max_msg_size,
    const std::vector<int>& pin_protocols, int max_cred_count,
    int max_cred_id_length) {
  // CTAP2 GetInfo 响应使用整数键，按数值排序: 1, 2, 3, 4, 5, 6, 7, 8, 10
  // 使用有序的键值对列表，然后按顺序构建 map
  std::vector<std::pair<int, cbor_item_t*>> items;

  // 1: versions (array of strings)
  {
    cbor_item_t* arr = cbor_new_definite_array(versions.size());
    for (const auto& v : versions) {
      if (!cbor_array_push(arr, cbor_move(cbor_build_string(v.c_str())))) {
        spdlog::warn("CBOR: cbor_array_push 失败");
      }
    }
    items.emplace_back(1, arr);
  }

  // 2: extensions (if not empty)
  if (!extensions.empty()) {
    cbor_item_t* arr = cbor_new_definite_array(extensions.size());
    for (const auto& e : extensions) {
      if (!cbor_array_push(arr, cbor_move(cbor_build_string(e.c_str())))) {
        spdlog::warn("CBOR: cbor_array_push 失败");
      }
    }
    items.emplace_back(2, arr);
  }

  // 3: aaguid (16 bytes)
  items.emplace_back(3, cbor_build_bytestring(aaguid.data(), aaguid.size()));

  // 4: options (map of string -> bool) - 按键的规范顺序
  if (!options.empty()) {
    std::vector<std::pair<std::string, cbor_item_t*>> opt_items;
    for (const auto& [k, v] : options) {
      opt_items.emplace_back(k, cbor_build_bool(v));
    }
    items.emplace_back(4, build_sorted_string_map(opt_items));
  }

  // 5: maxMsgSize
  items.emplace_back(5, cbor_build_uint32(max_msg_size));

  // 6: pinUvAuthProtocols (if not empty)
  if (!pin_protocols.empty()) {
    cbor_item_t* arr = cbor_new_definite_array(pin_protocols.size());
    for (int p : pin_protocols) {
      if (!cbor_array_push(arr, cbor_move(cbor_build_uint8(p)))) {
        spdlog::warn("CBOR: cbor_array_push 失败");
      }
    }
    items.emplace_back(6, arr);
  }

  // 7: maxCredentialCountInList
  if (max_cred_count > 0) {
    items.emplace_back(7, cbor_build_uint8(max_cred_count));
  }

  // 8: maxCredentialIdLength
  if (max_cred_id_length > 0) {
    items.emplace_back(8, cbor_build_uint16(max_cred_id_length));
  }

  // 10: algorithms - 按键规范顺序 ("alg" < "type")
  {
    std::vector<std::pair<std::string, cbor_item_t*>> alg_items;
    alg_items.emplace_back("alg", cbor_build_negint8(6));  // -7 = -(6+1)
    alg_items.emplace_back("type", cbor_build_string("public-key"));
    cbor_item_t* alg_map = build_sorted_string_map(alg_items);
    cbor_item_t* alg_arr = cbor_new_definite_array(1);
    if (!cbor_array_push(alg_arr, cbor_move(alg_map))) {
      spdlog::warn("CBOR: cbor_array_push 失败");
    }
    items.emplace_back(10, alg_arr);
  }

  // 按键排序（整数键按值升序）
  std::sort(items.begin(), items.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });

  // 构建最终 map
  cbor_item_t* root = cbor_new_definite_map(items.size());
  for (auto& [key, value] : items) {
    if (!cbor_map_add(root, {.key = cbor_move(cbor_build_uint8(key)),
                             .value = cbor_move(value)})) {
      spdlog::warn("CBOR: cbor_map_add 失败");
    }
  }

  auto result = encode(root);
  cbor_decref(&root);
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
  // 整数键顺序: 正整数按值升序 (1, 3)，负整数按绝对值升序 (-1, -2, -3)
  std::vector<std::pair<int, cbor_item_t*>> items;

  // 1: kty = 2 (EC2)
  items.emplace_back(1, cbor_build_uint8(2));

  // 3: alg = -7 (ES256)
  items.emplace_back(3, cbor_build_negint8(6));  // -7 = -(6+1)

  // -1: crv = 1 (P-256)
  items.emplace_back(-1, cbor_build_uint8(1));

  // -2: x coordinate (32 bytes)
  items.emplace_back(-2, cbor_build_bytestring(public_key.data() + 1, 32));

  // -3: y coordinate (32 bytes)
  items.emplace_back(-3, cbor_build_bytestring(public_key.data() + 33, 32));

  // COSE 规范：正整数先按值排序，负整数后按绝对值排序
  std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
    bool a_neg = a.first < 0;
    bool b_neg = b.first < 0;
    if (a_neg != b_neg) return !a_neg;             // 正数在前
    if (!a_neg) return a.first < b.first;          // 正数按值升序
    return std::abs(a.first) < std::abs(b.first);  // 负数按绝对值升序
  });

  // 构建 map
  cbor_item_t* root = cbor_new_definite_map(items.size());
  for (auto& [key, value] : items) {
    cbor_item_t* key_item = key >= 0 ? cbor_build_uint8(key)
                                     : cbor_build_negint8(std::abs(key) - 1);
    if (!cbor_map_add(
            root, {.key = cbor_move(key_item), .value = cbor_move(value)})) {
      spdlog::warn("CBOR: cbor_map_add 失败");
    }
  }

  auto result = encode(root);
  cbor_decref(&root);
  return result;
}

std::vector<uint8_t> CborEncoder::encode_make_credential_response(
    const std::string& fmt, const std::vector<uint8_t>& auth_data,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& x5c_cert) {
  // MakeCredential 响应: map(3) 整数键顺序: 1, 2, 3
  cbor_item_t* root = cbor_new_definite_map(3);

  // 1: fmt (string)
  if (!cbor_map_add(root,
                    {.key = cbor_move(cbor_build_uint8(1)),
                     .value = cbor_move(cbor_build_string(fmt.c_str()))})) {
    spdlog::warn("CBOR: cbor_map_add 失败");
  }

  // 2: authData (bytes)
  if (!cbor_map_add(root, {.key = cbor_move(cbor_build_uint8(2)),
                           .value = cbor_move(cbor_build_bytestring(
                               auth_data.data(), auth_data.size()))})) {
    spdlog::warn("CBOR: cbor_map_add 失败");
  }

  // 3: attStmt (map) - 按键规范顺序
  cbor_item_t* att_stmt;
  if (x5c_cert.empty()) {
    // Self attestation: {"alg": -7, "sig": ...}
    // 键顺序: "alg" < "sig" (长度相同，按字典序)
    std::vector<std::pair<std::string, cbor_item_t*>> att_items;
    att_items.emplace_back("alg", cbor_build_negint8(6));  // -7
    att_items.emplace_back(
        "sig", cbor_build_bytestring(signature.data(), signature.size()));
    att_stmt = build_sorted_string_map(att_items);
  } else {
    // Basic attestation: {"alg": -7, "sig": ..., "x5c": [...]}
    std::vector<std::pair<std::string, cbor_item_t*>> att_items;
    att_items.emplace_back("alg", cbor_build_negint8(6));  // -7
    att_items.emplace_back(
        "sig", cbor_build_bytestring(signature.data(), signature.size()));
    cbor_item_t* x5c_arr = cbor_new_definite_array(1);
    if (!cbor_array_push(x5c_arr, cbor_move(cbor_build_bytestring(
                                      x5c_cert.data(), x5c_cert.size())))) {
      spdlog::warn("CBOR: cbor_array_push 失败");
    }
    att_items.emplace_back("x5c", x5c_arr);
    att_stmt = build_sorted_string_map(att_items);
  }

  if (!cbor_map_add(root, {.key = cbor_move(cbor_build_uint8(3)),
                           .value = cbor_move(att_stmt)})) {
    spdlog::warn("CBOR: cbor_map_add 失败");
  }

  auto result = encode(root);
  cbor_decref(&root);
  return result;
}

std::vector<uint8_t> CborEncoder::encode_get_assertion_response(
    const std::vector<uint8_t>& credential_id,
    const std::vector<uint8_t>& auth_data,
    const std::vector<uint8_t>& signature, const std::vector<uint8_t>& user_id,
    const std::string& user_name) {
  // GetAssertion 响应: map(3 or 4) 整数键顺序: 1, 2, 3, 4
  bool has_user = !user_id.empty();
  cbor_item_t* root = cbor_new_definite_map(has_user ? 4 : 3);

  // 1: credential - 按键规范顺序 ("id" < "type")
  {
    std::vector<std::pair<std::string, cbor_item_t*>> cred_items;
    cred_items.emplace_back("id", cbor_build_bytestring(credential_id.data(),
                                                        credential_id.size()));
    cred_items.emplace_back("type", cbor_build_string("public-key"));
    if (!cbor_map_add(
            root, {.key = cbor_move(cbor_build_uint8(1)),
                   .value = cbor_move(build_sorted_string_map(cred_items))})) {
      spdlog::warn("CBOR: cbor_map_add 失败");
    }
  }

  // 2: authData
  if (!cbor_map_add(root, {.key = cbor_move(cbor_build_uint8(2)),
                           .value = cbor_move(cbor_build_bytestring(
                               auth_data.data(), auth_data.size()))})) {
    spdlog::warn("CBOR: cbor_map_add 失败");
  }

  // 3: signature
  if (!cbor_map_add(root, {.key = cbor_move(cbor_build_uint8(3)),
                           .value = cbor_move(cbor_build_bytestring(
                               signature.data(), signature.size()))})) {
    spdlog::warn("CBOR: cbor_map_add 失败");
  }

  // 4: user (optional) - 按键规范顺序 ("id" < "name")
  if (has_user) {
    std::vector<std::pair<std::string, cbor_item_t*>> user_items;
    user_items.emplace_back(
        "id", cbor_build_bytestring(user_id.data(), user_id.size()));
    if (!user_name.empty()) {
      user_items.emplace_back("name", cbor_build_string(user_name.c_str()));
    }
    if (!cbor_map_add(
            root, {.key = cbor_move(cbor_build_uint8(4)),
                   .value = cbor_move(build_sorted_string_map(user_items))})) {
      spdlog::warn("CBOR: cbor_map_add 失败");
    }
  }

  auto result = encode(root);
  cbor_decref(&root);
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
