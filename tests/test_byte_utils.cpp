#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <array>
#include <cstdint>
#include <vector>

#include "byte_utils.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

using namespace howdy;

// ── Concept static checks ────────────────────────────────────
static_assert(ByteRange<std::vector<uint8_t>>);
static_assert(ByteContainer<std::vector<uint8_t>>);
static_assert(!ByteRange<std::vector<int>>);
static_assert(ByteRange<std::array<uint8_t, 4>>);

// ── read_be32 ────────────────────────────────────────────────
TEST(ByteUtils, ReadBE32_KnownValue) {
  const uint8_t buf[] = {0x00, 0x00, 0x01, 0x00};
  EXPECT_EQ(read_be32(buf), 256u);
}

TEST(ByteUtils, ReadBE32_MaxValue) {
  const uint8_t buf[] = {0xFF, 0xFF, 0xFF, 0xFF};
  EXPECT_EQ(read_be32(buf), 0xFFFFFFFFu);
}

TEST(ByteUtils, ReadBE32_Zero) {
  const uint8_t buf[] = {0x00, 0x00, 0x00, 0x00};
  EXPECT_EQ(read_be32(buf), 0u);
}

TEST(ByteUtils, ReadBE32_HighByte) {
  const uint8_t buf[] = {0x12, 0x34, 0x56, 0x78};
  EXPECT_EQ(read_be32(buf), 0x12345678u);
}

// ── read_be16 ────────────────────────────────────────────────
TEST(ByteUtils, ReadBE16_KnownValue) {
  const uint8_t buf[] = {0x01, 0x00};
  EXPECT_EQ(read_be16(buf), 256u);
}

TEST(ByteUtils, ReadBE16_MaxValue) {
  const uint8_t buf[] = {0xFF, 0xFF};
  EXPECT_EQ(read_be16(buf), 0xFFFFu);
}

TEST(ByteUtils, ReadBE16_Zero) {
  const uint8_t buf[] = {0x00, 0x00};
  EXPECT_EQ(read_be16(buf), 0u);
}

// ── write_be32 ───────────────────────────────────────────────
TEST(ByteUtils, WriteBE32_Append) {
  std::vector<uint8_t> v;
  write_be32(v, 0x12345678u);
  ASSERT_EQ(v.size(), 4u);
  EXPECT_EQ(v[0], 0x12);
  EXPECT_EQ(v[1], 0x34);
  EXPECT_EQ(v[2], 0x56);
  EXPECT_EQ(v[3], 0x78);
}

TEST(ByteUtils, WriteBE32_AppendMultiple) {
  std::vector<uint8_t> v;
  write_be32(v, 0xAABBCCDDu);
  write_be32(v, 0x11223344u);
  ASSERT_EQ(v.size(), 8u);
  EXPECT_EQ(read_be32(v.data()), 0xAABBCCDDu);
  EXPECT_EQ(read_be32(v.data() + 4), 0x11223344u);
}

// ── write_be16 ───────────────────────────────────────────────
TEST(ByteUtils, WriteBE16_Append) {
  std::vector<uint8_t> v;
  write_be16(v, 0xABCDu);
  ASSERT_EQ(v.size(), 2u);
  EXPECT_EQ(v[0], 0xAB);
  EXPECT_EQ(v[1], 0xCD);
}

// ── write_be32_at / write_be16_at ────────────────────────────
TEST(ByteUtils, WriteBE32At_InPlace) {
  uint8_t buf[4] = {};
  write_be32_at(buf, 0xDEADBEEFu);
  EXPECT_EQ(buf[0], 0xDE);
  EXPECT_EQ(buf[1], 0xAD);
  EXPECT_EQ(buf[2], 0xBE);
  EXPECT_EQ(buf[3], 0xEF);
}

TEST(ByteUtils, WriteBE16At_InPlace) {
  uint8_t buf[2] = {};
  write_be16_at(buf, 0xCAFEu);
  EXPECT_EQ(buf[0], 0xCA);
  EXPECT_EQ(buf[1], 0xFE);
}

// ── Roundtrip ────────────────────────────────────────────────
TEST(ByteUtils, Roundtrip32) {
  for (uint32_t val : {0u, 1u, 255u, 256u, 65535u, 0x12345678u, 0xFFFFFFFFu}) {
    std::vector<uint8_t> v;
    write_be32(v, val);
    EXPECT_EQ(read_be32(v.data()), val) << "Failed for val=" << val;
  }
}

TEST(ByteUtils, Roundtrip16) {
  for (uint16_t val : {uint16_t{0}, uint16_t{1}, uint16_t{255}, uint16_t{256},
                       uint16_t{0xFFFF}}) {
    std::vector<uint8_t> v;
    write_be16(v, val);
    EXPECT_EQ(read_be16(v.data()), val) << "Failed for val=" << val;
  }
}

TEST(ByteUtils, Roundtrip32_At) {
  uint8_t buf[4];
  constexpr uint32_t val = 0xCAFEBABEu;
  write_be32_at(buf, val);
  EXPECT_EQ(read_be32(buf), val);
}

TEST(ByteUtils, Roundtrip16_At) {
  uint8_t buf[2];
  constexpr uint16_t val = 0xBEEFu;
  write_be16_at(buf, val);
  EXPECT_EQ(read_be16(buf), val);
}
