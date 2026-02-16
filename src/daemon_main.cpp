/**
 * howdy-fido2-daemon - 高权限守护进程
 *
 * 负责：
 * - UHID 设备管理
 * - TPM 加密/解密服务
 * - FIDO2/CTAP 协议处理
 *
 * 通过 D-Bus 与用户客户端通信：
 * - 验证请求 -> 客户端执行 PAM
 * - TPM 服务 -> 客户端存储加密凭据
 */

#include <spdlog/spdlog.h>

#include <argparse/argparse.hpp>
#include <atomic>
#include <csignal>
#include <print>

#include "dbus_interface.h"
#include "fido2_device.h"
#include "tpm_storage.h"

std::atomic<bool> g_running{true};

void signal_handler(int signum) {
  spdlog::info("收到信号 {}，正在退出...", signum);
  g_running.store(false);
}

int main(int argc, char* argv[]) {
  argparse::ArgumentParser program("howdy-fido2-daemon");
  program.add_description(
      "高权限守护进程，负责 UHID 和 TPM 操作。\n"
      "需要 root 权限或对 /dev/uhid 和 TPM 的访问权限。\n"
      "配合 howdy-fido2-client 使用进行 PAM 验证。");

  program.add_argument("-D", "--debug")
      .help("启用调试输出")
      .default_value(false)
      .implicit_value(true);

  try {
    program.parse_args(argc, argv);
  } catch (const std::exception& err) {
    std::print(stderr, "错误: {}\n", err.what());
    std::print(stderr, "\n{}", program.help().str());
    return 1;
  }

  bool debug = program.get<bool>("--debug");

  spdlog::set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");
  spdlog::set_level(debug ? spdlog::level::debug : spdlog::level::info);

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  spdlog::info("==================================");
  spdlog::info("  Howdy FIDO2 守护进程");
  spdlog::info("==================================");

  // 初始化 TPM
  howdy::TPMStorage tpm;
  bool tpm_available = tpm.initialize();
  if (!tpm_available) {
    spdlog::warn("TPM 不可用，凭据将不会被加密");
  }

  // 启动 D-Bus 服务
  howdy::DBusServer dbus_server;

  // 设置 TPM 回调
  dbus_server.set_tpm_seal_callback(
      [&tpm, tpm_available](
          const std::vector<uint8_t>& data) -> std::vector<uint8_t> {
        if (!tpm_available) {
          spdlog::warn("TPM: 不可用，返回原始数据");
          return data;  // 无 TPM 时返回原数据
        }
        return tpm.seal_data(data);
      });

  dbus_server.set_tpm_unseal_callback(
      [&tpm, tpm_available](
          const std::vector<uint8_t>& sealed) -> std::vector<uint8_t> {
        if (!tpm_available) {
          spdlog::warn("TPM: 不可用，返回原始数据");
          return sealed;  // 无 TPM 时返回原数据
        }
        return tpm.unseal_data(sealed);
      });

  // 创建 FIDO2 设备
  howdy::FIDO2Device device;

  // 设置凭据回调
  dbus_server.set_credentials_load_callback(
      [&device](const std::vector<uint8_t>& data) -> bool {
        spdlog::info("D-Bus: 收到凭据数据 ({} 字节)", data.size());
        return device.load_credentials_from_data(data);
      });

  dbus_server.set_credentials_get_callback(
      [&device, &dbus_server]() -> std::vector<uint8_t> {
        return device.get_credentials_data();
      });

  // 设置验证处理器
  device.set_auth_handler([&dbus_server](const std::string& operation,
                                         const std::string& rp_id) -> bool {
    spdlog::info("请求 PAM 验证: {} ({})", operation, rp_id);
    return dbus_server.request_auth(operation, rp_id, 60);
  });

  // 设置凭据变更回调
  device.set_credentials_changed_callback(
      [&dbus_server]() { dbus_server.notify_credentials_changed(); });

  if (!dbus_server.start()) {
    spdlog::error("无法启动 D-Bus 服务");
    spdlog::error("请检查 D-Bus 配置文件是否已安装");
    return 1;
  }

  if (!device.start()) {
    spdlog::error("启动 FIDO2 设备失败！");
    return 1;
  }

  spdlog::info("守护进程已启动，等待客户端连接...");
  spdlog::info("-----------------------------------");

  while (g_running.load()) {
    // 处理 D-Bus 事件
    dbus_server.process_events();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  spdlog::info("-----------------------------------");
  device.stop();
  dbus_server.stop();
  spdlog::info("守护进程已退出");

  return 0;
}
