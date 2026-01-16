#include "tpm_storage.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pwd.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <unistd.h>

#include <cstring>
#include <fstream>

namespace howdy {

// 文件名常量
static const char* SEALED_DATA_FILE = "credentials.sealed";
static const char* PRIMARY_KEY_FILE = "primary.ctx";

// AES-GCM 参数
static constexpr size_t AES_KEY_SIZE = 32;  // 256-bit
static constexpr size_t AES_GCM_IV_SIZE = 12;
static constexpr size_t AES_GCM_TAG_SIZE = 16;

TPMStorage::TPMStorage() = default;

TPMStorage::~TPMStorage() { cleanup(); }

void TPMStorage::cleanup() {
  if (primary_handle_ != 0) {
    Esys_FlushContext(static_cast<ESYS_CONTEXT*>(esys_context_),
                      primary_handle_);
    primary_handle_ = 0;
  }
  if (esys_context_) {
    Esys_Finalize(reinterpret_cast<ESYS_CONTEXT**>(&esys_context_));
    esys_context_ = nullptr;
  }
  available_ = false;
}

std::string TPMStorage::get_data_dir() const {
  const char* home = getenv("HOME");
  if (!home) {
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
      home = pw->pw_dir;
    }
  }
  if (!home) {
    return "/tmp/howdy-fido2";
  }
  return std::string(home) + "/.local/share/howdy-fido2";
}

std::string TPMStorage::get_storage_path() const {
  return get_data_dir() + "/" + SEALED_DATA_FILE;
}

bool TPMStorage::ensure_directory(const std::string& path) {
  struct stat st;
  if (stat(path.c_str(), &st) == 0) {
    return S_ISDIR(st.st_mode);
  }

  // 递归创建目录
  size_t pos = 0;
  while ((pos = path.find('/', pos + 1)) != std::string::npos) {
    std::string subpath = path.substr(0, pos);
    if (stat(subpath.c_str(), &st) != 0) {
      if (mkdir(subpath.c_str(), 0700) != 0 && errno != EEXIST) {
        return false;
      }
    }
  }
  if (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) {
    return false;
  }
  return true;
}

bool TPMStorage::initialize() {
  if (available_) {
    return true;
  }

  spdlog::debug("TPM: 初始化 TPM2 连接...");

  // 初始化 ESYS 上下文
  TSS2_RC rc = Esys_Initialize(reinterpret_cast<ESYS_CONTEXT**>(&esys_context_),
                               nullptr, nullptr);
  if (rc != TSS2_RC_SUCCESS) {
    last_error_ = "无法初始化 TPM2 ESYS 上下文";
    spdlog::warn("TPM: {} (rc=0x{:X})", last_error_, rc);
    return false;
  }

  // 创建主密钥
  if (!create_primary_key()) {
    cleanup();
    return false;
  }

  // 确保存储目录存在
  if (!ensure_directory(get_data_dir())) {
    last_error_ = "无法创建存储目录";
    spdlog::error("TPM: {}", last_error_);
    cleanup();
    return false;
  }

  available_ = true;
  spdlog::info("TPM: TPM2 封装存储已初始化");
  return true;
}

bool TPMStorage::create_primary_key() {
  auto* ctx = static_cast<ESYS_CONTEXT*>(esys_context_);

  spdlog::debug("TPM: 创建主密钥 (RSA 存储密钥)...");

  // 定义主密钥模板 (RSA 存储密钥，用作封装对象的父密钥)
  TPM2B_PUBLIC pub_template = {0};
  pub_template.publicArea.type = TPM2_ALG_RSA;
  pub_template.publicArea.nameAlg = TPM2_ALG_SHA256;
  pub_template.publicArea.objectAttributes =
      TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
      TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
      TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
  pub_template.publicArea.parameters.rsaDetail.symmetric.algorithm =
      TPM2_ALG_AES;
  pub_template.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
  pub_template.publicArea.parameters.rsaDetail.symmetric.mode.aes =
      TPM2_ALG_CFB;
  pub_template.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
  pub_template.publicArea.parameters.rsaDetail.keyBits = 2048;
  pub_template.publicArea.parameters.rsaDetail.exponent = 0;  // 默认 65537
  pub_template.publicArea.unique.rsa.size = 0;

  spdlog::debug("TPM: 主密钥模板 type=0x{:X}, attrs=0x{:X}",
                pub_template.publicArea.type,
                pub_template.publicArea.objectAttributes);

  // 敏感数据（空，让 TPM 生成）
  TPM2B_SENSITIVE_CREATE sensitive = {0};
  sensitive.sensitive.userAuth.size = 0;
  sensitive.sensitive.data.size = 0;

  // 创建数据
  TPM2B_DATA outside_info = {0};
  TPML_PCR_SELECTION pcr_select = {0};

  // 创建主密钥
  ESYS_TR primary;
  TPM2B_PUBLIC* out_public = nullptr;
  TPM2B_CREATION_DATA* creation_data = nullptr;
  TPM2B_DIGEST* creation_hash = nullptr;
  TPMT_TK_CREATION* creation_ticket = nullptr;

  TSS2_RC rc =
      Esys_CreatePrimary(ctx,
                         ESYS_TR_RH_OWNER,  // 在 owner hierarchy 下创建
                         ESYS_TR_PASSWORD,  // 授权会话
                         ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &pub_template,
                         &outside_info, &pcr_select, &primary, &out_public,
                         &creation_data, &creation_hash, &creation_ticket);

  spdlog::debug("TPM: Esys_CreatePrimary 返回 rc=0x{:X}", rc);

  // 清理输出
  Esys_Free(out_public);
  Esys_Free(creation_data);
  Esys_Free(creation_hash);
  Esys_Free(creation_ticket);

  if (rc != TSS2_RC_SUCCESS) {
    last_error_ = "无法创建 TPM 主密钥";
    spdlog::error("TPM: {} (rc=0x{:X})", last_error_, rc);
    return false;
  }

  primary_handle_ = primary;
  spdlog::debug("TPM: 主密钥创建成功, handle=0x{:X}", primary);
  return true;
}

// 内部静态函数：封装小数据块到 TPM (最大约 128 字节)
static bool seal_small(ESYS_CONTEXT* ctx, ESYS_TR primary,
                       const std::vector<uint8_t>& data, TPM2B_PUBLIC& out_pub,
                       TPM2B_PRIVATE& out_priv) {
  // 创建封装对象模板 (sealed data object)
  TPM2B_PUBLIC pub_template = {0};
  pub_template.publicArea.type = TPM2_ALG_KEYEDHASH;
  pub_template.publicArea.nameAlg = TPM2_ALG_SHA256;
  pub_template.publicArea.objectAttributes =
      TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_USERWITHAUTH;
  pub_template.publicArea.parameters.keyedHashDetail.scheme.scheme =
      TPM2_ALG_NULL;
  pub_template.publicArea.unique.keyedHash.size = 0;

  // 敏感数据
  TPM2B_SENSITIVE_CREATE sensitive = {0};
  sensitive.sensitive.userAuth.size = 0;
  sensitive.sensitive.data.size = static_cast<uint16_t>(data.size());
  memcpy(sensitive.sensitive.data.buffer, data.data(), data.size());

  TPM2B_DATA outside_info = {0};
  TPML_PCR_SELECTION pcr_select = {0};

  TPM2B_PRIVATE* priv_ptr = nullptr;
  TPM2B_PUBLIC* pub_ptr = nullptr;
  TPM2B_CREATION_DATA* creation_data = nullptr;
  TPM2B_DIGEST* creation_hash = nullptr;
  TPMT_TK_CREATION* creation_ticket = nullptr;

  TSS2_RC rc = Esys_Create(ctx, primary, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &sensitive, &pub_template,
                           &outside_info, &pcr_select, &priv_ptr, &pub_ptr,
                           &creation_data, &creation_hash, &creation_ticket);

  Esys_Free(creation_data);
  Esys_Free(creation_hash);
  Esys_Free(creation_ticket);

  if (rc != TSS2_RC_SUCCESS) {
    spdlog::error("TPM: seal_small 失败 (rc=0x{:X})", rc);
    Esys_Free(priv_ptr);
    Esys_Free(pub_ptr);
    return false;
  }

  out_pub = *pub_ptr;
  out_priv = *priv_ptr;
  Esys_Free(priv_ptr);
  Esys_Free(pub_ptr);
  return true;
}

// 内部静态函数：从 TPM 解封小数据块
static std::optional<std::vector<uint8_t>> unseal_small(
    ESYS_CONTEXT* ctx, ESYS_TR primary, const TPM2B_PUBLIC& in_pub,
    const TPM2B_PRIVATE& in_priv) {
  ESYS_TR loaded_handle;

  // 需要非 const 拷贝
  TPM2B_PUBLIC pub_copy = in_pub;
  TPM2B_PRIVATE priv_copy = in_priv;

  TSS2_RC rc = Esys_Load(ctx, primary, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                         ESYS_TR_NONE, &priv_copy, &pub_copy, &loaded_handle);
  if (rc != TSS2_RC_SUCCESS) {
    spdlog::error("TPM: unseal_small Load 失败 (rc=0x{:X})", rc);
    return std::nullopt;
  }

  TPM2B_SENSITIVE_DATA* unsealed_data = nullptr;
  rc = Esys_Unseal(ctx, loaded_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                   ESYS_TR_NONE, &unsealed_data);

  Esys_FlushContext(ctx, loaded_handle);

  if (rc != TSS2_RC_SUCCESS) {
    spdlog::error("TPM: unseal_small Unseal 失败 (rc=0x{:X})", rc);
    return std::nullopt;
  }

  std::vector<uint8_t> result(unsealed_data->buffer,
                              unsealed_data->buffer + unsealed_data->size);
  Esys_Free(unsealed_data);
  return result;
}

bool TPMStorage::seal(const std::vector<uint8_t>& data) {
  if (!available_) {
    last_error_ = "TPM 未初始化";
    return false;
  }

  if (data.empty()) {
    last_error_ = "数据为空";
    return false;
  }

  spdlog::debug("TPM seal: 数据大小={} 字节 (使用混合加密)", data.size());

  // 1. 生成随机 AES 密钥
  std::vector<uint8_t> aes_key(AES_KEY_SIZE);
  if (RAND_bytes(aes_key.data(), AES_KEY_SIZE) != 1) {
    last_error_ = "生成随机密钥失败";
    return false;
  }

  // 2. 用 TPM 封装 AES 密钥
  TPM2B_PUBLIC sealed_pub;
  TPM2B_PRIVATE sealed_priv;
  auto* ctx = static_cast<ESYS_CONTEXT*>(esys_context_);
  ESYS_TR primary = primary_handle_;

  if (!seal_small(ctx, primary, aes_key, sealed_pub, sealed_priv)) {
    last_error_ = "TPM 封装 AES 密钥失败";
    return false;
  }

  spdlog::debug("TPM seal: AES 密钥已封装到 TPM");

  // 3. 用 AES-GCM 加密数据
  std::vector<uint8_t> iv(AES_GCM_IV_SIZE);
  if (RAND_bytes(iv.data(), AES_GCM_IV_SIZE) != 1) {
    last_error_ = "生成 IV 失败";
    return false;
  }

  std::vector<uint8_t> ciphertext(data.size() + AES_GCM_TAG_SIZE);
  std::vector<uint8_t> tag(AES_GCM_TAG_SIZE);

  EVP_CIPHER_CTX* evp_ctx = EVP_CIPHER_CTX_new();
  if (!evp_ctx) {
    last_error_ = "创建加密上下文失败";
    return false;
  }

  int len = 0;
  int ciphertext_len = 0;

  bool encrypt_ok =
      EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) == 1 &&
      EVP_EncryptInit_ex(evp_ctx, nullptr, nullptr, aes_key.data(),
                         iv.data()) == 1 &&
      EVP_EncryptUpdate(evp_ctx, ciphertext.data(), &len, data.data(),
                        static_cast<int>(data.size())) == 1;
  ciphertext_len = len;

  if (encrypt_ok) {
    encrypt_ok =
        EVP_EncryptFinal_ex(evp_ctx, ciphertext.data() + len, &len) == 1;
    ciphertext_len += len;
  }

  if (encrypt_ok) {
    encrypt_ok = EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG,
                                     AES_GCM_TAG_SIZE, tag.data()) == 1;
  }

  EVP_CIPHER_CTX_free(evp_ctx);

  if (!encrypt_ok) {
    last_error_ = "AES-GCM 加密失败";
    return false;
  }

  ciphertext.resize(ciphertext_len);

  // 4. 保存到文件: [sealed_pub][sealed_priv][iv][tag][ciphertext]
  std::string filepath = get_storage_path();
  std::ofstream file(filepath, std::ios::binary);
  if (!file) {
    last_error_ = "无法打开文件写入";
    return false;
  }

  // 序列化 TPM 对象
  uint8_t pub_buf[sizeof(TPM2B_PUBLIC)];
  size_t pub_size = 0;
  Tss2_MU_TPM2B_PUBLIC_Marshal(&sealed_pub, pub_buf, sizeof(pub_buf),
                               &pub_size);

  uint8_t priv_buf[sizeof(TPM2B_PRIVATE)];
  size_t priv_size = 0;
  Tss2_MU_TPM2B_PRIVATE_Marshal(&sealed_priv, priv_buf, sizeof(priv_buf),
                                &priv_size);

  // 写入格式: pub_len(4) + pub + priv_len(4) + priv + iv + tag + cipher_len(4)
  // + cipher
  uint32_t pub_len = static_cast<uint32_t>(pub_size);
  uint32_t priv_len = static_cast<uint32_t>(priv_size);
  uint32_t cipher_len = static_cast<uint32_t>(ciphertext.size());

  file.write(reinterpret_cast<char*>(&pub_len), 4);
  file.write(reinterpret_cast<char*>(pub_buf), pub_size);
  file.write(reinterpret_cast<char*>(&priv_len), 4);
  file.write(reinterpret_cast<char*>(priv_buf), priv_size);
  file.write(reinterpret_cast<char*>(iv.data()), AES_GCM_IV_SIZE);
  file.write(reinterpret_cast<char*>(tag.data()), AES_GCM_TAG_SIZE);
  file.write(reinterpret_cast<char*>(&cipher_len), 4);
  file.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());

  file.close();

  // 清除敏感数据
  OPENSSL_cleanse(aes_key.data(), aes_key.size());

  spdlog::info("TPM: 数据已加密保存到 {} ({} 字节)", filepath,
               ciphertext.size());
  return true;
}

std::optional<std::vector<uint8_t>> TPMStorage::unseal() {
  if (!available_) {
    last_error_ = "TPM 未初始化";
    return std::nullopt;
  }

  std::string filepath = get_storage_path();
  std::ifstream file(filepath, std::ios::binary);
  if (!file) {
    last_error_ = "无法打开封装文件";
    return std::nullopt;
  }

  // 1. 读取 sealed public
  uint32_t pub_len;
  file.read(reinterpret_cast<char*>(&pub_len), 4);
  if (pub_len > sizeof(TPM2B_PUBLIC)) {
    last_error_ = "文件格式错误";
    return std::nullopt;
  }

  std::vector<uint8_t> pub_buf(pub_len);
  file.read(reinterpret_cast<char*>(pub_buf.data()), pub_len);

  TPM2B_PUBLIC sealed_pub = {0};
  size_t offset = 0;
  Tss2_MU_TPM2B_PUBLIC_Unmarshal(pub_buf.data(), pub_len, &offset, &sealed_pub);

  // 2. 读取 sealed private
  uint32_t priv_len;
  file.read(reinterpret_cast<char*>(&priv_len), 4);
  if (priv_len > sizeof(TPM2B_PRIVATE)) {
    last_error_ = "文件格式错误";
    return std::nullopt;
  }

  std::vector<uint8_t> priv_buf(priv_len);
  file.read(reinterpret_cast<char*>(priv_buf.data()), priv_len);

  TPM2B_PRIVATE sealed_priv = {0};
  offset = 0;
  Tss2_MU_TPM2B_PRIVATE_Unmarshal(priv_buf.data(), priv_len, &offset,
                                  &sealed_priv);

  // 3. 读取 IV 和 Tag
  std::vector<uint8_t> iv(AES_GCM_IV_SIZE);
  std::vector<uint8_t> tag(AES_GCM_TAG_SIZE);
  file.read(reinterpret_cast<char*>(iv.data()), AES_GCM_IV_SIZE);
  file.read(reinterpret_cast<char*>(tag.data()), AES_GCM_TAG_SIZE);

  // 4. 读取密文
  uint32_t cipher_len;
  file.read(reinterpret_cast<char*>(&cipher_len), 4);
  std::vector<uint8_t> ciphertext(cipher_len);
  file.read(reinterpret_cast<char*>(ciphertext.data()), cipher_len);

  file.close();

  // 5. 从 TPM 解封 AES 密钥
  auto* ctx = static_cast<ESYS_CONTEXT*>(esys_context_);
  ESYS_TR primary = primary_handle_;
  auto aes_key_opt = unseal_small(ctx, primary, sealed_pub, sealed_priv);
  if (!aes_key_opt) {
    last_error_ = "TPM 解封 AES 密钥失败";
    return std::nullopt;
  }

  auto& aes_key = *aes_key_opt;
  spdlog::debug("TPM unseal: AES 密钥已从 TPM 解封");

  // 6. 用 AES-GCM 解密数据
  std::vector<uint8_t> plaintext(ciphertext.size());

  EVP_CIPHER_CTX* evp_ctx = EVP_CIPHER_CTX_new();
  if (!evp_ctx) {
    last_error_ = "创建解密上下文失败";
    return std::nullopt;
  }

  int len = 0;
  int plaintext_len = 0;

  bool decrypt_ok =
      EVP_DecryptInit_ex(evp_ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) == 1 &&
      EVP_DecryptInit_ex(evp_ctx, nullptr, nullptr, aes_key.data(),
                         iv.data()) == 1 &&
      EVP_DecryptUpdate(evp_ctx, plaintext.data(), &len, ciphertext.data(),
                        static_cast<int>(ciphertext.size())) == 1;
  plaintext_len = len;

  if (decrypt_ok) {
    decrypt_ok = EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG,
                                     AES_GCM_TAG_SIZE, tag.data()) == 1;
  }

  if (decrypt_ok) {
    decrypt_ok =
        EVP_DecryptFinal_ex(evp_ctx, plaintext.data() + len, &len) == 1;
    plaintext_len += len;
  }

  EVP_CIPHER_CTX_free(evp_ctx);

  // 清除敏感数据
  OPENSSL_cleanse(aes_key.data(), aes_key.size());

  if (!decrypt_ok) {
    last_error_ = "AES-GCM 解密失败 (数据可能被篡改)";
    return std::nullopt;
  }

  plaintext.resize(plaintext_len);
  spdlog::debug("TPM unseal: 数据解密成功 ({} 字节)", plaintext.size());
  return plaintext;
}

bool TPMStorage::has_sealed_data() const {
  struct stat st;
  return stat(get_storage_path().c_str(), &st) == 0;
}

bool TPMStorage::remove_sealed_data() {
  std::string filepath = get_storage_path();
  if (unlink(filepath.c_str()) != 0 && errno != ENOENT) {
    last_error_ = "删除封装文件失败";
    return false;
  }
  return true;
}

// ============== CredentialSerializer 实现 ==============

std::vector<uint8_t> CredentialSerializer::serialize(
    const std::vector<Credential>& credentials) {
  std::vector<uint8_t> result;

  // 版本号
  uint8_t version = 1;
  result.push_back(version);

  // 凭据数量
  uint32_t count = static_cast<uint32_t>(credentials.size());
  result.push_back((count >> 24) & 0xFF);
  result.push_back((count >> 16) & 0xFF);
  result.push_back((count >> 8) & 0xFF);
  result.push_back(count & 0xFF);

  for (const auto& cred : credentials) {
    // credential_id
    uint16_t len = static_cast<uint16_t>(cred.credential_id.size());
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    result.insert(result.end(), cred.credential_id.begin(),
                  cred.credential_id.end());

    // private_key
    len = static_cast<uint16_t>(cred.private_key.size());
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    result.insert(result.end(), cred.private_key.begin(),
                  cred.private_key.end());

    // app_id
    len = static_cast<uint16_t>(cred.app_id.size());
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    result.insert(result.end(), cred.app_id.begin(), cred.app_id.end());

    // user_id
    len = static_cast<uint16_t>(cred.user_id.size());
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    result.insert(result.end(), cred.user_id.begin(), cred.user_id.end());

    // user_name
    len = static_cast<uint16_t>(cred.user_name.size());
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    result.insert(result.end(), cred.user_name.begin(), cred.user_name.end());

    // rp_id
    len = static_cast<uint16_t>(cred.rp_id.size());
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    result.insert(result.end(), cred.rp_id.begin(), cred.rp_id.end());

    // counter
    result.push_back((cred.counter >> 24) & 0xFF);
    result.push_back((cred.counter >> 16) & 0xFF);
    result.push_back((cred.counter >> 8) & 0xFF);
    result.push_back(cred.counter & 0xFF);
  }

  return result;
}

std::vector<CredentialSerializer::Credential> CredentialSerializer::deserialize(
    const std::vector<uint8_t>& data) {
  std::vector<Credential> result;

  if (data.size() < 5) {
    return result;
  }

  size_t offset = 0;

  // 版本号
  uint8_t version = data[offset++];
  if (version != 1) {
    spdlog::error("TPM: 不支持的凭据版本: {}", version);
    return result;
  }

  // 凭据数量
  uint32_t count = (static_cast<uint32_t>(data[offset]) << 24) |
                   (static_cast<uint32_t>(data[offset + 1]) << 16) |
                   (static_cast<uint32_t>(data[offset + 2]) << 8) |
                   static_cast<uint32_t>(data[offset + 3]);
  offset += 4;

  auto read_bytes = [&](std::vector<uint8_t>& out) -> bool {
    if (offset + 2 > data.size()) return false;
    uint16_t len = (static_cast<uint16_t>(data[offset]) << 8) |
                   static_cast<uint16_t>(data[offset + 1]);
    offset += 2;
    if (offset + len > data.size()) return false;
    out.assign(data.begin() + offset, data.begin() + offset + len);
    offset += len;
    return true;
  };

  auto read_string = [&](std::string& out) -> bool {
    if (offset + 2 > data.size()) return false;
    uint16_t len = (static_cast<uint16_t>(data[offset]) << 8) |
                   static_cast<uint16_t>(data[offset + 1]);
    offset += 2;
    if (offset + len > data.size()) return false;
    out.assign(reinterpret_cast<const char*>(data.data() + offset), len);
    offset += len;
    return true;
  };

  for (uint32_t i = 0; i < count; i++) {
    Credential cred;

    if (!read_bytes(cred.credential_id)) break;
    if (!read_bytes(cred.private_key)) break;
    if (!read_bytes(cred.app_id)) break;
    if (!read_bytes(cred.user_id)) break;
    if (!read_string(cred.user_name)) break;
    if (!read_string(cred.rp_id)) break;

    if (offset + 4 > data.size()) break;
    cred.counter = (static_cast<uint32_t>(data[offset]) << 24) |
                   (static_cast<uint32_t>(data[offset + 1]) << 16) |
                   (static_cast<uint32_t>(data[offset + 2]) << 8) |
                   static_cast<uint32_t>(data[offset + 3]);
    offset += 4;

    result.push_back(std::move(cred));
  }

  return result;
}

}  // namespace howdy
