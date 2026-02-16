#include "device_detector.h"

#include <fido.h>
#include <fido/credman.h>
#include <spdlog/spdlog.h>

#include <cstring>
#include <memory>

namespace howdy {

// libfido2 设备列表的 RAII 包装
struct FidoDevListDeleter {
  void operator()(fido_dev_info_t* list) const {
    if (list) fido_dev_info_free(&list, 0);
  }
};

using FidoDevListPtr = std::unique_ptr<fido_dev_info_t, FidoDevListDeleter>;

std::vector<FIDO2DeviceInfo> DeviceDetector::detect_other_devices() {
  std::vector<FIDO2DeviceInfo> devices;

  fido_dev_info_t* dev_list = nullptr;
  size_t dev_count = 0;
  constexpr size_t max_devices = 64;

  // 分配设备列表
  dev_list = fido_dev_info_new(max_devices);
  if (!dev_list) {
    spdlog::error("无法分配设备列表");
    return devices;
  }

  // 使用 RAII 管理内存
  FidoDevListPtr dev_list_ptr(dev_list);

  // 枚举 FIDO 设备
  int ret = fido_dev_info_manifest(dev_list, max_devices, &dev_count);
  if (ret != FIDO_OK) {
    spdlog::debug("枚举 FIDO 设备失败: {}", fido_strerr(ret));
    return devices;
  }

  spdlog::debug("libfido2 检测到 {} 个 FIDO 设备", dev_count);

  // 遍历每个设备
  for (size_t i = 0; i < dev_count; i++) {
    const fido_dev_info_t* di = fido_dev_info_ptr(dev_list, i);
    if (!di) continue;

    FIDO2DeviceInfo info;

    // 获取设备路径
    const char* path = fido_dev_info_path(di);
    if (path) {
      info.path = path;
    }

    // 获取厂商和产品名称
    const char* manufacturer = fido_dev_info_manufacturer_string(di);
    const char* product = fido_dev_info_product_string(di);

    if (manufacturer && product) {
      info.product_name = std::string(manufacturer) + " " + product;
    } else if (product) {
      info.product_name = product;
    } else if (manufacturer) {
      info.product_name = manufacturer;
    }

    // 获取 VID/PID
    info.vendor_id = fido_dev_info_vendor(di);
    info.product_id = fido_dev_info_product(di);

    // 排除我们自己的虚拟设备
    if (is_our_virtual_device(info)) {
      spdlog::debug("跳过 Howdy 虚拟设备: {} ({})", info.path,
                    info.product_name);
      continue;
    }

    // 添加到设备列表
    devices.push_back(std::move(info));
    spdlog::debug("检测到 FIDO2 设备: {} (VID:{:04X} PID:{:04X} {})",
                  devices.back().path, devices.back().vendor_id,
                  devices.back().product_id, devices.back().product_name);
  }

  return devices;
}

// 使用 libfido2 验证设备是否为 FIDO2 设备
bool DeviceDetector::is_fido2_device(const std::string& path) {
  // 尝试打开设备
  fido_dev_t* dev = fido_dev_new();
  if (!dev) {
    return false;
  }

  bool is_fido = false;

  // 尝试打开并获取设备信息
  if (fido_dev_open(dev, path.c_str()) == FIDO_OK) {
    // 尝试获取设备信息以确认是 FIDO2 设备
    if (fido_dev_get_cbor_info(dev, nullptr) == FIDO_OK) {
      is_fido = true;
    }
    fido_dev_close(dev);
  }

  fido_dev_free(&dev);
  return is_fido;
}

bool DeviceDetector::is_our_virtual_device(const FIDO2DeviceInfo& info) {
  return info.product_name.contains("Howdy FIDO2 Device");
}

}  // namespace howdy
