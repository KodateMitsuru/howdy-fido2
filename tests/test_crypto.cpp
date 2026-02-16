#include <gtest/gtest.h>
#include <openssl/x509.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <vector>

#include "crypto.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

using namespace howdy;

// ── ECKeyPair generation ─────────────────────────────────────
TEST(ECKeyPair, Generate_Success) {
  ECKeyPair kp;
  EXPECT_TRUE(kp.generate());
  EXPECT_TRUE(kp.is_valid());
}

TEST(ECKeyPair, Generate_PublicKeySize) {
  ECKeyPair kp;
  ASSERT_TRUE(kp.generate());
  auto pub = kp.get_public_key();
  ASSERT_EQ(pub.size(), 65u);
  EXPECT_EQ(pub[0], 0x04);  // 未压缩格式标记
}

TEST(ECKeyPair, Generate_PrivateKeySize) {
  ECKeyPair kp;
  ASSERT_TRUE(kp.generate());
  auto priv = kp.get_private_key();
  EXPECT_EQ(priv.size(), 32u);
}

TEST(ECKeyPair, Generate_UniqueKeys) {
  ECKeyPair a, b;
  ASSERT_TRUE(a.generate());
  ASSERT_TRUE(b.generate());
  EXPECT_NE(a.get_public_key(), b.get_public_key());
  EXPECT_NE(a.get_private_key(), b.get_private_key());
}

// ── Sign / Verify ────────────────────────────────────────────
TEST(ECKeyPair, SignVerify_Roundtrip) {
  ECKeyPair kp;
  ASSERT_TRUE(kp.generate());

  std::vector<uint8_t> msg = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
  auto sig = kp.sign(msg);
  ASSERT_FALSE(sig.empty());
  EXPECT_TRUE(kp.verify(msg, sig));
}

TEST(ECKeyPair, Verify_WrongData) {
  ECKeyPair kp;
  ASSERT_TRUE(kp.generate());

  std::vector<uint8_t> msg_a = {0x01, 0x02, 0x03};
  std::vector<uint8_t> msg_b = {0x04, 0x05, 0x06};
  auto sig = kp.sign(msg_a);
  EXPECT_FALSE(kp.verify(msg_b, sig));
}

TEST(ECKeyPair, Verify_WrongSignature) {
  ECKeyPair kp;
  ASSERT_TRUE(kp.generate());

  std::vector<uint8_t> msg = {0xAA, 0xBB};
  std::vector<uint8_t> garbage_sig = {0x30, 0x06, 0x02, 0x01,
                                      0x00, 0x02, 0x01, 0x00};
  EXPECT_FALSE(kp.verify(msg, garbage_sig));
}

TEST(ECKeyPair, SignVerify_EmptyData) {
  ECKeyPair kp;
  ASSERT_TRUE(kp.generate());

  std::vector<uint8_t> empty;
  auto sig = kp.sign(empty);
  ASSERT_FALSE(sig.empty());
  EXPECT_TRUE(kp.verify(empty, sig));
}

TEST(ECKeyPair, SignVerify_LargeData) {
  ECKeyPair kp;
  ASSERT_TRUE(kp.generate());

  std::vector<uint8_t> big(4096, 0x42);
  auto sig = kp.sign(big);
  ASSERT_FALSE(sig.empty());
  EXPECT_TRUE(kp.verify(big, sig));
}

// ── set_private_key ──────────────────────────────────────────
TEST(ECKeyPair, SetPrivateKey_PublicKeyConsistent) {
  ECKeyPair orig;
  ASSERT_TRUE(orig.generate());
  auto priv = orig.get_private_key();
  auto expected_pub = orig.get_public_key();

  ECKeyPair restored;
  ASSERT_TRUE(restored.set_private_key(priv));
  EXPECT_EQ(restored.get_public_key(), expected_pub);
}

TEST(ECKeyPair, SetPrivateKey_CanSign) {
  ECKeyPair orig;
  ASSERT_TRUE(orig.generate());
  auto priv = orig.get_private_key();

  ECKeyPair restored;
  ASSERT_TRUE(restored.set_private_key(priv));

  std::vector<uint8_t> msg = {0x01, 0x02, 0x03};
  auto sig = restored.sign(msg);
  ASSERT_FALSE(sig.empty());
  // 用原始密钥验证
  EXPECT_TRUE(orig.verify(msg, sig));
}

TEST(ECKeyPair, SetPrivateKey_WrongSize) {
  ECKeyPair kp;
  std::vector<uint8_t> short_key(16, 0xAA);
  EXPECT_FALSE(kp.set_private_key(short_key));
  EXPECT_FALSE(kp.is_valid());
}

TEST(ECKeyPair, SetPrivateKey_Empty) {
  ECKeyPair kp;
  EXPECT_FALSE(kp.set_private_key({}));
}

// ── Move semantics ───────────────────────────────────────────
TEST(ECKeyPair, MoveConstruct) {
  ECKeyPair a;
  ASSERT_TRUE(a.generate());
  auto pub = a.get_public_key();

  ECKeyPair b = std::move(a);
  EXPECT_TRUE(b.is_valid());
  EXPECT_EQ(b.get_public_key(), pub);
  EXPECT_FALSE(a.is_valid());  // NOLINT: testing moved-from state
}

TEST(ECKeyPair, MoveAssign) {
  ECKeyPair a, b;
  ASSERT_TRUE(a.generate());
  auto pub = a.get_public_key();

  b = std::move(a);
  EXPECT_TRUE(b.is_valid());
  EXPECT_EQ(b.get_public_key(), pub);
  EXPECT_FALSE(a.is_valid());  // NOLINT: testing moved-from state
}

// ── CryptoUtils::sha256 ─────────────────────────────────────
TEST(CryptoUtils, SHA256_Empty) {
  auto hash = CryptoUtils::sha256({});
  ASSERT_EQ(hash.size(), 32u);
  // SHA-256("") = e3b0c442...
  EXPECT_EQ(hash[0], 0xE3);
  EXPECT_EQ(hash[1], 0xB0);
  EXPECT_EQ(hash[2], 0xC4);
  EXPECT_EQ(hash[3], 0x42);
}

TEST(CryptoUtils, SHA256_KnownVector) {
  // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 ...
  std::vector<uint8_t> abc = {0x61, 0x62, 0x63};
  auto hash = CryptoUtils::sha256(abc);
  ASSERT_EQ(hash.size(), 32u);
  EXPECT_EQ(hash[0], 0xBA);
  EXPECT_EQ(hash[1], 0x78);
  EXPECT_EQ(hash[2], 0x16);
  EXPECT_EQ(hash[3], 0xBF);
}

TEST(CryptoUtils, SHA256_Deterministic) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03};
  EXPECT_EQ(CryptoUtils::sha256(data), CryptoUtils::sha256(data));
}

// ── CryptoUtils::random_bytes ────────────────────────────────
TEST(CryptoUtils, RandomBytes_CorrectLength) {
  for (size_t len : {0u, 1u, 16u, 32u, 256u}) {
    auto bytes = CryptoUtils::random_bytes(len);
    EXPECT_EQ(bytes.size(), len) << "len=" << len;
  }
}

TEST(CryptoUtils, RandomBytes_Unique) {
  auto a = CryptoUtils::random_bytes(32);
  auto b = CryptoUtils::random_bytes(32);
  EXPECT_NE(a, b);
}

// ── CryptoUtils::generate_self_signed_cert ───────────────────
TEST(CryptoUtils, SelfSignedCert_ValidDER) {
  ECKeyPair kp;
  ASSERT_TRUE(kp.generate());

  auto cert_der = CryptoUtils::generate_self_signed_cert(kp, "Test Cert");
  ASSERT_FALSE(cert_der.empty());

  // 用 OpenSSL 验证是合法的 DER 编码 X.509
  const uint8_t* p = cert_der.data();
  X509* cert = d2i_X509(nullptr, &p, static_cast<long>(cert_der.size()));
  ASSERT_NE(cert, nullptr);
  X509_free(cert);
}

TEST(CryptoUtils, SelfSignedCert_CNMatchesSubject) {
  ECKeyPair kp;
  ASSERT_TRUE(kp.generate());

  auto cert_der =
      CryptoUtils::generate_self_signed_cert(kp, "Howdy FIDO2", 365);
  ASSERT_FALSE(cert_der.empty());

  const uint8_t* p = cert_der.data();
  X509* cert = d2i_X509(nullptr, &p, static_cast<long>(cert_der.size()));
  ASSERT_NE(cert, nullptr);

  X509_NAME* subj = X509_get_subject_name(cert);
  char cn_buf[256] = {};
  X509_NAME_get_text_by_NID(subj, NID_commonName, cn_buf, sizeof(cn_buf));
  EXPECT_STREQ(cn_buf, "Howdy FIDO2");

  X509_free(cert);
}
