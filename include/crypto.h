#pragma once

#include <openssl/ec.h>
#include <openssl/evp.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace howdy {

// ECDSA P-256 密钥对
class ECKeyPair {
 public:
  ECKeyPair();
  ~ECKeyPair();

  // 禁止拷贝
  ECKeyPair(const ECKeyPair&) = delete;
  ECKeyPair& operator=(const ECKeyPair&) = delete;

  // 允许移动
  ECKeyPair(ECKeyPair&& other) noexcept;
  ECKeyPair& operator=(ECKeyPair&& other) noexcept;

  // 生成新密钥对
  bool generate();

  // 获取公钥 (未压缩格式: 04 || x || y, 65 字节)
  std::vector<uint8_t> get_public_key() const;

  // 获取私钥 (32 字节)
  std::vector<uint8_t> get_private_key() const;

  // 从私钥恢复
  bool set_private_key(const std::vector<uint8_t>& priv_key);

  // ECDSA 签名 (返回 DER 编码的签名)
  std::vector<uint8_t> sign(const std::vector<uint8_t>& data) const;

  // 验证签名
  bool verify(const std::vector<uint8_t>& data,
              const std::vector<uint8_t>& signature) const;

  bool is_valid() const { return pkey_ != nullptr; }

  // 允许 CryptoUtils 访问私有成员
  friend class CryptoUtils;

 private:
  EVP_PKEY* pkey_ = nullptr;
};

// 加密工具函数
class CryptoUtils {
 public:
  // SHA-256 哈希
  static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

  // 生成随机字节
  static std::vector<uint8_t> random_bytes(size_t len);

  // 生成自签名 X.509 证书
  static std::vector<uint8_t> generate_self_signed_cert(
      const ECKeyPair& key_pair, const std::string& common_name,
      int validity_days = 3650);
};

}  // namespace howdy
