#include "config.h"

#include <spdlog/spdlog.h>

#include <cctype>
#include <fstream>
#include <ranges>

namespace howdy {

std::optional<Config> Config::load(const std::string& path) {
  Config config;

  std::ifstream file(path);
  if (!file.is_open()) {
    spdlog::debug("配置文件未找到: {}, 使用默认配置", path);
    return config;  // 返回默认配置
  }

  std::string line;
  int line_number = 0;

  while (std::getline(file, line)) {
    line_number++;

    // 去除注释
    if (auto comment_pos = line.find('#'); comment_pos != std::string::npos) {
      line = line.substr(0, comment_pos);
    }

    auto trim = [](std::string_view sv) {
      auto is_space = [](unsigned char c) { return std::isspace(c); };
      auto trimmed = sv | std::views::drop_while(is_space) |
                     std::views::reverse | std::views::drop_while(is_space) |
                     std::views::reverse;
      return std::string(trimmed.begin(), trimmed.end());
    };

    line = trim(line);

    if (line.empty()) {
      continue;  // 空行
    }

    // 解析 key=value
    auto eq_pos = line.find('=');
    if (eq_pos == std::string::npos) {
      spdlog::warn("配置文件 {} 行 {}: 无效格式", path, line_number);
      continue;
    }

    std::string key = trim(line.substr(0, eq_pos));
    std::string value = trim(line.substr(eq_pos + 1));

    if (key == "device_policy") {
      config.device_policy = parse_policy(value);
    } else if (key == "pam_service") {
      config.pam_service = value;
    } else if (key == "verification_timeout") {
      try {
        config.verification_timeout = std::stoi(value);
      } catch (...) {
        spdlog::warn("配置文件 {} 行 {}: 无效的超时值", path, line_number);
      }
    } else if (key == "debug_logging") {
      config.debug_logging =
          (value == "true" || value == "1" || value == "yes");
    } else {
      spdlog::debug("配置文件 {} 行 {}: 未知配置项 '{}'", path, line_number,
                    key);
    }
  }

  spdlog::info("配置已加载: device_policy={}",
               policy_to_string(config.device_policy));
  return config;
}

DevicePolicy Config::parse_policy(const std::string& str) {
  auto to_lower = [](char c) {
    return std::tolower(static_cast<unsigned char>(c));
  };
  auto lower = str | std::views::transform(to_lower);
  std::string lower_str(lower.begin(), lower.end());

  if (lower_str == "always_respond") {
    return DevicePolicy::ALWAYS_RESPOND;
  } else if (lower_str == "fallback" || lower_str == "silent_fallback" ||
             lower_str == "prefer_hardware") {
    // 兼容旧配置
    return DevicePolicy::FALLBACK;
  } else {
    spdlog::warn("未知的设备策略: {}, 使用默认值", str);
    return DevicePolicy::FALLBACK;
  }
}

std::string Config::policy_to_string(DevicePolicy policy) {
  switch (policy) {
    case DevicePolicy::ALWAYS_RESPOND:
      return "always_respond";
    case DevicePolicy::FALLBACK:
      return "fallback";
    default:
      return "unknown";
  }
}

}  // namespace howdy
