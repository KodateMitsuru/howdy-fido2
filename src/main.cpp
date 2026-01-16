#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <csignal>
#include <cstring>

#include "fido2_device.h"

std::atomic<bool> g_running{true};

void signal_handler(int signum) {
  spdlog::info("收到信号 {}，正在退出...", signum);
  g_running.store(false);
}

void print_usage(const char* program) {
  fmt::print(
      "用法: {} [选项]\n\n"
      "选项:\n"
      "  -s, --service NAME  PAM 服务名 (默认: howdy-fido2)\n"
      "  -D, --debug         启用调试输出\n"
      "  -h, --help          显示此帮助信息\n\n"
      "此程序创建一个虚拟 FIDO2 安全密钥设备，使用 PAM 进行用户验证。\n"
      "需要对 /dev/uhid 的访问权限 (可通过 udev 规则配置)。\n\n"
      "PAM 配置:\n"
      "  将 pam.d/howdy-fido2 复制到 /etc/pam.d/\n\n"
      "示例:\n"
      "  {}                    # 使用默认 PAM 服务\n"
      "  {} -s login           # 使用 login PAM 服务\n",
      program, program, program);
}

int main(int argc, char* argv[]) {
  bool debug = false;
  std::string pam_service = "howdy-fido2";

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      print_usage(argv[0]);
      return 0;
    } else if (arg == "-s" || arg == "--service") {
      if (i + 1 < argc) {
        pam_service = argv[++i];
      } else {
        spdlog::error("--service 需要参数");
        return 1;
      }
    } else if (arg == "-D" || arg == "--debug") {
      debug = true;
    } else {
      spdlog::error("未知选项: {}", arg);
      print_usage(argv[0]);
      return 1;
    }
  }

  // 初始化日志
  spdlog::set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");
  spdlog::set_level(debug ? spdlog::level::debug : spdlog::level::info);

  // 设置信号处理
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  spdlog::info("==================================");
  spdlog::info("  Howdy FIDO2 虚拟设备模拟器");
  spdlog::info("==================================");

  howdy::FIDO2Device device;
  device.set_pam_service(pam_service);

  spdlog::info("PAM 服务: {}", pam_service);

  if (!device.start()) {
    spdlog::error("启动 FIDO2 设备失败！");
    spdlog::error("请检查:");
    spdlog::error("  1. 是否以 root 权限运行");
    spdlog::error("  2. 内核是否支持 UHID (/dev/uhid)");
    return 1;
  }

  spdlog::info("设备已启动，按 Ctrl+C 退出");
  spdlog::info("等待 FIDO2 请求...");
  spdlog::info("-----------------------------------");

  // 主循环
  while (g_running.load() && device.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  spdlog::info("-----------------------------------");
  device.stop();
  spdlog::info("程序已退出");

  return 0;
}
