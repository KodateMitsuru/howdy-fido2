#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <vector>

#include "tpm_storage.h"

using namespace howdy;

// ── Fixture: 初始化 TPM，不可用时自动跳过 ────────────────────
class TPMStorageTest : public ::testing::Test {
 protected:
  TPMStorage tpm;

  void SetUp() override {
    if (!tpm.initialize()) {
      GTEST_SKIP() << "TPM not available: " << tpm.last_error();
    }
  }
};

// ── 初始化 ───────────────────────────────────────────────────
TEST_F(TPMStorageTest, Initialize_Success) { EXPECT_TRUE(tpm.is_available()); }

// ── seal / unseal roundtrip ──────────────────────────────────
TEST_F(TPMStorageTest, SealUnseal_EmptyData) {
  // 空数据 seal 返回空 — 实现拒绝加密空数据（无意义操作）
  std::vector<uint8_t> data;
  auto sealed = tpm.seal_data(data);
  EXPECT_TRUE(sealed.empty()) << "seal_data should reject empty input";
}

TEST_F(TPMStorageTest, SealUnseal_SmallData) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                               0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
  auto sealed = tpm.seal_data(data);
  ASSERT_FALSE(sealed.empty()) << tpm.last_error();
  auto unsealed = tpm.unseal_data(sealed);
  EXPECT_EQ(unsealed, data);
}

TEST_F(TPMStorageTest, SealUnseal_LargeData) {
  // 10 KB of sequential data
  std::vector<uint8_t> data(10240);
  std::iota(data.begin(), data.end(), uint8_t{0});
  auto sealed = tpm.seal_data(data);
  ASSERT_FALSE(sealed.empty()) << tpm.last_error();
  auto unsealed = tpm.unseal_data(sealed);
  EXPECT_EQ(unsealed, data);
}

TEST_F(TPMStorageTest, SealUnseal_Integrity) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
  auto sealed = tpm.seal_data(data);
  ASSERT_FALSE(sealed.empty());
  ASSERT_GT(sealed.size(), 10u);

  // 篡改密文中间字节
  sealed[sealed.size() / 2] ^= 0xFF;
  auto unsealed = tpm.unseal_data(sealed);
  EXPECT_TRUE(unsealed.empty()) << "Tampered ciphertext should fail to unseal";
}

TEST_F(TPMStorageTest, SealUnseal_Truncated) {
  std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC};
  auto sealed = tpm.seal_data(data);
  ASSERT_FALSE(sealed.empty());

  // 截断到一半
  sealed.resize(sealed.size() / 2);
  auto unsealed = tpm.unseal_data(sealed);
  EXPECT_TRUE(unsealed.empty()) << "Truncated ciphertext should fail";
}

TEST_F(TPMStorageTest, DoubleSeal_DifferentCiphertext) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03};
  auto sealed1 = tpm.seal_data(data);
  auto sealed2 = tpm.seal_data(data);
  ASSERT_FALSE(sealed1.empty());
  ASSERT_FALSE(sealed2.empty());
  // 随机 IV → 密文应该不同
  EXPECT_NE(sealed1, sealed2);
  // 但 unseal 结果应该一致
  EXPECT_EQ(tpm.unseal_data(sealed1), data);
  EXPECT_EQ(tpm.unseal_data(sealed2), data);
}

// ── 未初始化时的行为 ─────────────────────────────────────────
TEST(TPMStorageNoInit, Unseal_WithoutInit) {
  TPMStorage tpm;
  // 不调用 initialize()
  EXPECT_FALSE(tpm.is_available());
  auto result = tpm.unseal_data({0x01, 0x02});
  EXPECT_TRUE(result.empty());
}

TEST(TPMStorageNoInit, Seal_WithoutInit) {
  TPMStorage tpm;
  auto result = tpm.seal_data({0x01, 0x02});
  EXPECT_TRUE(result.empty());
}
