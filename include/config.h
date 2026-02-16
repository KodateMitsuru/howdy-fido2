#pragma once

#include <optional>
#include <string>

namespace howdy {

// FIDO2 设备行为策略
enum class DevicePolicy {
  ALWAYS_RESPOND,  // 总是响应，忽略其他设备
  FALLBACK         // 如果有其他设备则回避，否则响应（默认）
};

struct Config {
  // 设备策略配置
  DevicePolicy device_policy = DevicePolicy::FALLBACK;

  // PAM 服务名称
  std::string pam_service = "howdy-fido2";

  // 验证超时时间（秒）
  int verification_timeout = 30;

  // 是否启用调试日志
  bool debug_logging = false;

  // 加载配置文件
  static std::optional<Config> load(
      const std::string& path = "/etc/howdy-fido2/config.conf");

  // 从字符串解析策略
  static DevicePolicy parse_policy(const std::string& str);
  static std::string policy_to_string(DevicePolicy policy);
};

}  // namespace howdy
