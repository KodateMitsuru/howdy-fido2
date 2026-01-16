#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace howdy {

/**
 * TPM 封装存储
 *
 * 使用 TPM2 的 Seal/Unseal 功能保护凭据数据：
 * - 数据使用 TPM 内部密钥加密
 * - 密钥绑定到 TPM，无法导出
 * - 可选绑定 PCR 状态（系统启动状态）
 *
 * 存储位置: ~/.local/share/howdy-fido2/credentials.sealed
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
   * 封装数据（加密并存储）
   * @param data 要封装的数据
   * @return true 如果成功
   */
  bool seal(const std::vector<uint8_t>& data);

  /**
   * 解封数据（读取并解密）
   * @return 解封的数据，如果失败返回 nullopt
   */
  std::optional<std::vector<uint8_t>> unseal();

  /**
   * 检查是否有已封装的数据
   */
  bool has_sealed_data() const;

  /**
   * 删除已封装的数据
   */
  bool remove_sealed_data();

  /**
   * 获取最后一次错误信息
   */
  const std::string& last_error() const { return last_error_; }

  /**
   * 获取存储文件路径
   */
  std::string get_storage_path() const;

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

  // 获取数据目录
  std::string get_data_dir() const;

  // 确保目录存在
  bool ensure_directory(const std::string& path);
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
