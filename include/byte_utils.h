#pragma once

#include <bit>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <ranges>
#include <vector>

namespace howdy {

// C++23 concept: 连续字节范围
template <typename R>
concept ByteRange = std::ranges::contiguous_range<R> &&
                    std::same_as<std::ranges::range_value_t<R>, uint8_t>;

// C++23 concept: 可追加的字节容器 (支持 insert)
template <typename C>
concept ByteContainer = ByteRange<C> && requires(C c, const uint8_t* p) {
  c.insert(c.end(), p, p + 1);
};

// 大端序读写工具函数 (利用 C++23 std::byteswap + C++20 std::endian)

inline uint32_t read_be32(const uint8_t* p) {
  uint32_t val;
  std::memcpy(&val, p, 4);
  if constexpr (std::endian::native == std::endian::little)
    val = std::byteswap(val);
  return val;
}

inline uint16_t read_be16(const uint8_t* p) {
  uint16_t val;
  std::memcpy(&val, p, 2);
  if constexpr (std::endian::native == std::endian::little)
    val = std::byteswap(val);
  return val;
}

inline void write_be32(ByteContainer auto& v, uint32_t val) {
  if constexpr (std::endian::native == std::endian::little)
    val = std::byteswap(val);
  auto* p = reinterpret_cast<const uint8_t*>(&val);
  v.insert(v.end(), p, p + 4);
}

inline void write_be16(ByteContainer auto& v, uint16_t val) {
  if constexpr (std::endian::native == std::endian::little)
    val = std::byteswap(val);
  auto* p = reinterpret_cast<const uint8_t*>(&val);
  v.insert(v.end(), p, p + 2);
}

// 写入大端序到指定偏移位置
inline void write_be32_at(uint8_t* dest, uint32_t val) {
  if constexpr (std::endian::native == std::endian::little)
    val = std::byteswap(val);
  std::memcpy(dest, &val, 4);
}

inline void write_be16_at(uint8_t* dest, uint16_t val) {
  if constexpr (std::endian::native == std::endian::little)
    val = std::byteswap(val);
  std::memcpy(dest, &val, 2);
}

}  // namespace howdy
