#include "crypto.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <iostream>

namespace howdy {

ECKeyPair::ECKeyPair() = default;

ECKeyPair::~ECKeyPair() {
  if (pkey_) {
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
  }
}

ECKeyPair::ECKeyPair(ECKeyPair&& other) noexcept : pkey_(other.pkey_) {
  other.pkey_ = nullptr;
}

ECKeyPair& ECKeyPair::operator=(ECKeyPair&& other) noexcept {
  if (this != &other) {
    if (pkey_) {
      EVP_PKEY_free(pkey_);
    }
    pkey_ = other.pkey_;
    other.pkey_ = nullptr;
  }
  return *this;
}

bool ECKeyPair::generate() {
  if (pkey_) {
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (!ctx) {
    std::cerr << "Crypto: EVP_PKEY_CTX_new_id failed" << std::endl;
    return false;
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    std::cerr << "Crypto: EVP_PKEY_keygen_init failed" << std::endl;
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
    std::cerr << "Crypto: EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed"
              << std::endl;
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  if (EVP_PKEY_keygen(ctx, &pkey_) <= 0) {
    std::cerr << "Crypto: EVP_PKEY_keygen failed" << std::endl;
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  EVP_PKEY_CTX_free(ctx);
  return true;
}

std::vector<uint8_t> ECKeyPair::get_public_key() const {
  std::vector<uint8_t> result;
  if (!pkey_) return result;

  // 获取公钥大小
  size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(pkey_, OSSL_PKEY_PARAM_PUB_KEY, nullptr,
                                      0, &len) != 1) {
    std::cerr << "Crypto: Failed to get public key length" << std::endl;
    return result;
  }

  result.resize(len);
  if (EVP_PKEY_get_octet_string_param(pkey_, OSSL_PKEY_PARAM_PUB_KEY,
                                      result.data(), len, &len) != 1) {
    std::cerr << "Crypto: Failed to get public key" << std::endl;
    return {};
  }

  return result;
}

std::vector<uint8_t> ECKeyPair::get_private_key() const {
  std::vector<uint8_t> result;
  if (!pkey_) return result;

  BIGNUM* priv_bn = nullptr;
  if (EVP_PKEY_get_bn_param(pkey_, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) != 1) {
    std::cerr << "Crypto: Failed to get private key" << std::endl;
    return result;
  }

  int bn_size = BN_num_bytes(priv_bn);
  result.resize(32);  // P-256 private key is 32 bytes

  // 填充到32字节
  int offset = 32 - bn_size;
  if (offset > 0) {
    std::fill(result.begin(), result.begin() + offset, 0);
  }
  BN_bn2bin(priv_bn, result.data() + offset);

  BN_free(priv_bn);
  return result;
}

bool ECKeyPair::set_private_key(const std::vector<uint8_t>& private_key) {
  if (private_key.size() != 32) {
    std::cerr << "Crypto: Invalid private key size" << std::endl;
    return false;
  }

  if (pkey_) {
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
  }

  // 从私钥创建 BIGNUM
  BIGNUM* priv_bn = BN_bin2bn(private_key.data(), private_key.size(), nullptr);
  if (!priv_bn) {
    std::cerr << "Crypto: Failed to create BIGNUM from private key"
              << std::endl;
    return false;
  }

  // 获取 P-256 曲线参数
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (!group) {
    BN_free(priv_bn);
    return false;
  }

  // 计算公钥点
  EC_POINT* pub_point = EC_POINT_new(group);
  if (!pub_point ||
      !EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr)) {
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_free(priv_bn);
    return false;
  }

  // 获取公钥的未压缩格式
  size_t pub_len = EC_POINT_point2oct(
      group, pub_point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  std::vector<uint8_t> pub_key(pub_len);
  EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                     pub_key.data(), pub_len, nullptr);

  EC_POINT_free(pub_point);
  EC_GROUP_free(group);

  // 使用 OpenSSL 3.x API 构建密钥
  OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
  if (!param_bld) {
    BN_free(priv_bn);
    return false;
  }

  OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                  "prime256v1", 0);
  OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn);
  OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                   pub_key.data(), pub_key.size());

  OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);
  OSSL_PARAM_BLD_free(param_bld);
  BN_free(priv_bn);

  if (!params) {
    return false;
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!ctx) {
    OSSL_PARAM_free(params);
    return false;
  }

  if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
      EVP_PKEY_fromdata(ctx, &pkey_, EVP_PKEY_KEYPAIR, params) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    return false;
  }

  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  return true;
}

std::vector<uint8_t> ECKeyPair::sign(const std::vector<uint8_t>& data) const {
  std::vector<uint8_t> result;
  if (!pkey_) return result;

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) return result;

  if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey_) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    return result;
  }

  if (EVP_DigestSignUpdate(md_ctx, data.data(), data.size()) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    return result;
  }

  size_t sig_len = 0;
  if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    return result;
  }

  result.resize(sig_len);
  if (EVP_DigestSignFinal(md_ctx, result.data(), &sig_len) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    return {};
  }

  result.resize(sig_len);
  EVP_MD_CTX_free(md_ctx);
  return result;
}

bool ECKeyPair::verify(const std::vector<uint8_t>& data,
                       const std::vector<uint8_t>& signature) const {
  if (!pkey_) return false;

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) return false;

  if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey_) <=
      0) {
    EVP_MD_CTX_free(md_ctx);
    return false;
  }

  if (EVP_DigestVerifyUpdate(md_ctx, data.data(), data.size()) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    return false;
  }

  int result =
      EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size());
  EVP_MD_CTX_free(md_ctx);
  return result == 1;
}

// CryptoUtils 实现

std::vector<uint8_t> CryptoUtils::sha256(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  SHA256(data.data(), data.size(), hash.data());
  return hash;
}

std::vector<uint8_t> CryptoUtils::random_bytes(size_t len) {
  std::vector<uint8_t> result(len);
  RAND_bytes(result.data(), len);
  return result;
}

std::vector<uint8_t> CryptoUtils::generate_self_signed_cert(
    const ECKeyPair& key_pair, const std::string& common_name, int days) {
  std::vector<uint8_t> result;

  X509* x509 = X509_new();
  if (!x509) return result;

  // 设置版本为 V3
  X509_set_version(x509, 2);

  // 设置序列号
  ASN1_INTEGER* serial = ASN1_INTEGER_new();
  ASN1_INTEGER_set(serial, 1);
  X509_set_serialNumber(x509, serial);
  ASN1_INTEGER_free(serial);

  // 设置有效期
  X509_gmtime_adj(X509_getm_notBefore(x509), 0);
  X509_gmtime_adj(X509_getm_notAfter(x509), 60 * 60 * 24 * days);

  // 设置公钥
  X509_set_pubkey(x509, key_pair.pkey_);

  // 设置主题和颁发者 (自签名，所以相同)
  X509_NAME* name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (const unsigned char*)common_name.c_str(), -1, -1,
                             0);
  X509_set_issuer_name(x509, name);

  // 签名
  if (X509_sign(x509, key_pair.pkey_, EVP_sha256()) <= 0) {
    X509_free(x509);
    return result;
  }

  // 导出为 DER 格式
  int len = i2d_X509(x509, nullptr);
  if (len > 0) {
    result.resize(len);
    unsigned char* p = result.data();
    i2d_X509(x509, &p);
  }

  X509_free(x509);
  return result;
}

}  // namespace howdy
