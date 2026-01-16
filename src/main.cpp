#include <atomic>
#include <csignal>
#include <cstring>
#include <iostream>

#include "fido2_device.h"

std::atomic<bool> g_running{true};

void signal_handler(int signum) {
  std::cout << "\n收到信号 " << signum << "，正在退出..." << std::endl;
  g_running.store(false);
}

void print_usage(const char* program) {
  std::cout
      << "用法: " << program << " [选项]\n"
      << "\n"
      << "选项:\n"
      << "  -p, --pam           使用 PAM 验证用户 (默认)\n"
      << "  -n, --no-pam        禁用 PAM 验证\n"
      << "  -s, --service NAME  PAM 服务名 (默认: howdy-fido2)\n"
      << "  -a, --allow         默认允许 (PAM 禁用或失败时)\n"
      << "  -d, --deny          默认拒绝 (PAM 禁用或失败时)\n"
      << "  -h, --help          显示此帮助信息\n"
      << "\n"
      << "此程序创建一个虚拟 FIDO2 安全密钥设备，使用 PAM 进行用户验证。\n"
      << "需要 root 权限或对 /dev/uhid 的访问权限。\n"
      << "\n"
      << "PAM 配置:\n"
      << "  将 pam.d/howdy-fido2 复制到 /etc/pam.d/\n"
      << "  默认配置使用 pam_howdy.so (人脸识别)\n"
      << "\n"
      << "示例:\n"
      << "  sudo " << program << "                    # 使用 PAM 验证\n"
      << "  sudo " << program << " --no-pam --allow   # 禁用 PAM，默认允许\n"
      << "  sudo " << program << " -s login           # 使用 login PAM 服务\n"
      << std::endl;
}

int main(int argc, char* argv[]) {
  bool use_pam = true;
  bool default_allow = true;
  std::string pam_service = "howdy-fido2";

  // 解析命令行参数
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      print_usage(argv[0]);
      return 0;
    } else if (arg == "-p" || arg == "--pam") {
      use_pam = true;
    } else if (arg == "-n" || arg == "--no-pam") {
      use_pam = false;
    } else if (arg == "-s" || arg == "--service") {
      if (i + 1 < argc) {
        pam_service = argv[++i];
      } else {
        std::cerr << "错误: --service 需要参数" << std::endl;
        return 1;
      }
    } else if (arg == "-a" || arg == "--allow") {
      default_allow = true;
    } else if (arg == "-d" || arg == "--deny") {
      default_allow = false;
    } else {
      std::cerr << "未知选项: " << arg << std::endl;
      print_usage(argv[0]);
      return 1;
    }
  }

  // 设置信号处理
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  std::cout << "==================================" << std::endl;
  std::cout << "  Howdy FIDO2 虚拟设备模拟器" << std::endl;
  std::cout << "==================================" << std::endl;
  std::cout << std::endl;

  howdy::FIDO2Device device;
  device.set_use_pam(use_pam);
  device.set_default_auth_result(default_allow);
  device.set_pam_service(pam_service);

  std::cout << "PAM 验证: " << (use_pam ? "启用 ✓" : "禁用 ✗") << std::endl;
  if (use_pam) {
    std::cout << "PAM 服务: " << pam_service << std::endl;
  }
  std::cout << "默认结果: " << (default_allow ? "允许" : "拒绝")
            << " (PAM 禁用/失败时)" << std::endl;
  std::cout << std::endl;

  if (!device.start()) {
    std::cerr << "启动 FIDO2 设备失败！" << std::endl;
    std::cerr << "请检查:" << std::endl;
    std::cerr << "  1. 是否以 root 权限运行" << std::endl;
    std::cerr << "  2. 内核是否支持 UHID (/dev/uhid)" << std::endl;
    return 1;
  }

  std::cout << "设备已启动，按 Ctrl+C 退出" << std::endl;
  std::cout << std::endl;
  std::cout << "等待 FIDO2 请求..." << std::endl;
  std::cout << "-----------------------------------" << std::endl;

  // 主循环
  while (g_running.load() && device.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  std::cout << "-----------------------------------" << std::endl;
  device.stop();
  std::cout << "程序已退出" << std::endl;

  return 0;
}
