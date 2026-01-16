#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace howdy {

/**
 * TPM 封装存储服务
 *
 * 使用 TPM2 的 Seal/Unseal 功能保护凭据数据：
 * - 数据使用 TPM 内部密钥加密
 * - 密钥绑定到 TPM，无法导出
 *
 * 仅提供内存加密/解密服务，文件存储由客户端管理
 */
class TPMStorage {
 public:
  TPMStorage();
  ~TPMStorage();

  // 禁用拷贝
  TPMStorage(const TPMStorage&) = delete;
  TPMStorage& operator=(const TPMStorage&) = delete;

  /**
   * 初始化 TPM 连接
   * @return true 如果 TPM 可用并初始化成功
   */
  bool initialize();

  /**
   * 检查 TPM 是否可用
   */
  bool is_available() const { return available_; }

  /**
   * 封装数据（加密）
   * @param data 要封装的数据
   * @return 封装后的数据，如果失败返回空
   */
  std::vector<uint8_t> seal_data(const std::vector<uint8_t>& data);

  /**
   * 解封数据（解密）
   * @param sealed_data 封装的数据
   * @return 解封的数据，如果失败返回空
   */
  std::vector<uint8_t> unseal_data(const std::vector<uint8_t>& sealed_data);

  /**
   * 获取最后一次错误信息
   */
  const std::string& last_error() const { return last_error_; }

 private:
  // TPM 上下文
  void* esys_context_ = nullptr;  // ESYS_CONTEXT*
  uint32_t primary_handle_ = 0;   // ESYS_TR

  bool available_ = false;
  std::string last_error_;

  // 创建主密钥（SRK 派生）
  bool create_primary_key();

  // 清理资源
  void cleanup();
};

/**
 * 凭据序列化/反序列化
 */
class CredentialSerializer {
 public:
  // 凭据结构
  struct Credential {
    std::vector<uint8_t> credential_id;
    std::vector<uint8_t> private_key;
    std::vector<uint8_t> app_id;
    std::vector<uint8_t> user_id;
    std::string user_name;
    std::string rp_id;
    uint32_t counter;
  };

  /**
   * 序列化凭据列表
   */
  static std::vector<uint8_t> serialize(
      const std::vector<Credential>& credentials);

  /**
   * 反序列化凭据列表
   */
  static std::vector<Credential> deserialize(const std::vector<uint8_t>& data);
};

}  // namespace howdy
