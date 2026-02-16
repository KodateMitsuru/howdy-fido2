#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace howdy {

// FIDO2 设备信息
struct FIDO2DeviceInfo {
  std::string path;          // 设备路径，如 /dev/hidraw0
  std::string product_name;  // 产品名称
  uint16_t vendor_id;        // 供应商 ID
  uint16_t product_id;       // 产品 ID
};

class DeviceDetector {
 public:
  // 检测系统中的所有 FIDO2 设备（除了自己）
  static std::vector<FIDO2DeviceInfo> detect_other_devices();

 private:
  // 检查设备是否为 FIDO2 设备（使用 libfido2）
  static bool is_fido2_device(const std::string& path);

  // 判断是否为我们自己创建的虚拟设备
  static bool is_our_virtual_device(const FIDO2DeviceInfo& info);
};

}  // namespace howdy
