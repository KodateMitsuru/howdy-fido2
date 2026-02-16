/**
 * howdy-fido2-client - 用户客户端
 *
 * 负责：
 * - PAM 用户验证
 * - 凭据文件管理（~/.local/share/howdy-fido2/）
 * - 通过 D-Bus 使用守护进程的 TPM 服务
 *
 * 以普通用户权限运行
 */

#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <unistd.h>

#include <argparse/argparse.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <print>

#include "dbus_interface.h"
#include "pam_auth.h"

namespace fs = std::filesystem;

std::atomic<bool> g_running{true};

void signal_handler(int signum) {
  spdlog::info("收到信号 {}，正在退出...", signum);
  g_running.store(false);
}

// 用户验证状态缓存
struct AuthCache {
  bool verified = false;
  std::chrono::steady_clock::time_point time;
  static constexpr int TIMEOUT_SECONDS = 30;

  bool is_valid() const {
    if (!verified) return false;
    auto elapsed = std::chrono::steady_clock::now() - time;
    return elapsed < std::chrono::seconds(TIMEOUT_SECONDS);
  }

  void set_verified() {
    verified = true;
    time = std::chrono::steady_clock::now();
  }

  void clear() { verified = false; }
};

// 凭据文件管理
class CredentialsFile {
 public:
  CredentialsFile() {
    // 获取用户数据目录
    const char* home = getenv("HOME");
    if (home) {
      data_dir_ = fs::path(home) / ".local" / "share" / "howdy-fido2";
      credentials_file_ = data_dir_ / "credentials.sealed";
    }
  }

  bool ensure_directory() {
    if (data_dir_.empty()) return false;
    try {
      if (!fs::exists(data_dir_)) {
        fs::create_directories(data_dir_);
        // 设置目录权限为 700
        chmod(data_dir_.c_str(), 0700);
      }
      return true;
    } catch (const std::exception& e) {
      spdlog::error("无法创建数据目录: {}", e.what());
      return false;
    }
  }

  std::vector<uint8_t> load() {
    if (credentials_file_.empty() || !fs::exists(credentials_file_)) {
      return {};
    }
    try {
      std::ifstream file(credentials_file_, std::ios::binary);
      if (!file) return {};

      file.seekg(0, std::ios::end);
      size_t size = file.tellg();
      file.seekg(0, std::ios::beg);

      std::vector<uint8_t> data(size);
      file.read(reinterpret_cast<char*>(data.data()), size);
      return data;
    } catch (const std::exception& e) {
      spdlog::error("无法读取凭据文件: {}", e.what());
      return {};
    }
  }

  bool save(const std::vector<uint8_t>& data) {
    if (credentials_file_.empty()) return false;
    if (!ensure_directory()) return false;

    try {
      std::ofstream file(credentials_file_, std::ios::binary | std::ios::trunc);
      if (!file) {
        spdlog::error("无法打开凭据文件进行写入");
        return false;
      }
      file.write(reinterpret_cast<const char*>(data.data()), data.size());
      // 设置文件权限为 600
      chmod(credentials_file_.c_str(), 0600);
      return true;
    } catch (const std::exception& e) {
      spdlog::error("无法保存凭据文件: {}", e.what());
      return false;
    }
  }

  std::string path() const { return credentials_file_.string(); }

 private:
  fs::path data_dir_;
  fs::path credentials_file_;
};

int main(int argc, char* argv[]) {
  argparse::ArgumentParser program("howdy-fido2-client");
  program.add_description(
      "用户客户端，负责 PAM 验证和凭据管理。\n"
      "以普通用户权限运行，通过 D-Bus 与守护进程通信。");

  program.add_argument("-s", "--service")
      .help("PAM 服务名")
      .default_value(std::string("howdy-fido2"))
      .metavar("NAME");

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
  std::string pam_service = program.get<std::string>("--service");

  spdlog::set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");
  spdlog::set_level(debug ? spdlog::level::debug : spdlog::level::info);

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  spdlog::info("==================================");
  spdlog::info("  Howdy FIDO2 客户端");
  spdlog::info("==================================");
  spdlog::info("PAM 服务: {}", pam_service);

  AuthCache auth_cache;
  CredentialsFile cred_file;

  spdlog::info("凭据文件: {}", cred_file.path());

  // 连接 D-Bus
  howdy::DBusClient client;

  client.set_pam_callback(
      [&pam_service, &auth_cache](const std::string& operation,
                                  const std::string& rp_id) -> bool {
        spdlog::info("");
        spdlog::info("========================================");
        spdlog::info("🔐 FIDO2 验证请求: {}", operation);
        if (!rp_id.empty()) {
          spdlog::info("   RP: {}", rp_id);
        }
        spdlog::info("========================================");

        // 检查缓存
        if (auth_cache.is_valid()) {
          auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::steady_clock::now() - auth_cache.time)
                             .count();
          spdlog::info("✅ 使用缓存的验证结果 (剩余 {} 秒)",
                       AuthCache::TIMEOUT_SECONDS - elapsed);
          return true;
        }

        // 执行 PAM 验证
        spdlog::info("🔍 启动 PAM 验证 (服务: {})...", pam_service);

        howdy::PAMAuthenticator pam(pam_service);
        pam.set_timeout(30);
        pam.set_prompt_callback(
            [](const std::string& msg) { spdlog::info("   📢 {}", msg); });

        auto result = pam.authenticate();

        spdlog::info("========================================");

        switch (result) {
          case howdy::PAMResult::SUCCESS:
            spdlog::info("✅ PAM 验证成功!");
            spdlog::info("📝 验证结果已缓存 ({} 秒有效)",
                         AuthCache::TIMEOUT_SECONDS);
            auth_cache.set_verified();
            return true;

          case howdy::PAMResult::AUTH_FAILED:
            spdlog::warn("❌ PAM 验证失败: {}", pam.last_error());
            auth_cache.clear();
            return false;

          case howdy::PAMResult::USER_CANCELLED:
            spdlog::info("⏹️  用户取消或超时");
            auth_cache.clear();
            return false;

          case howdy::PAMResult::ERROR:
          default:
            spdlog::error("⚠️  PAM 错误: {}", pam.last_error());
            auth_cache.clear();
            return false;
        }
      });

  // 凭据变更回调 - 保存到本地文件
  client.set_credentials_changed_callback([&client, &cred_file]() {
    spdlog::info("凭据已变更，保存到本地...");
    auto data = client.get_credentials();
    if (!data.empty()) {
      // 使用 TPM 加密后保存
      auto sealed = client.seal_data(data);
      if (!sealed.empty()) {
        if (cred_file.save(sealed)) {
          spdlog::info("凭据已保存 ({} 字节)", sealed.size());
        }
      } else {
        // TPM 不可用，直接保存（不推荐）
        spdlog::warn("TPM 不可用，凭据将以明文保存");
        cred_file.save(data);
      }
    }
  });

  // 连接重试循环
  while (g_running.load()) {
    if (!client.connect()) {
      spdlog::warn("无法连接到 D-Bus，5 秒后重试...");
      std::this_thread::sleep_for(std::chrono::seconds(5));
      continue;
    }

    // 等待 daemon 服务就绪
    spdlog::info("已连接到 D-Bus，等待 daemon 服务...");
    bool service_ready = false;
    for (int retry = 0; retry < 30 && g_running.load(); retry++) {
      if (client.is_service_ready()) {
        service_ready = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if (!service_ready) {
      spdlog::warn("daemon 服务未就绪，5 秒后重试...");
      client.disconnect();
      std::this_thread::sleep_for(std::chrono::seconds(5));
      continue;
    }

    spdlog::info("已连接到守护进程");

    // 加载并上传凭据
    auto sealed_data = cred_file.load();
    if (!sealed_data.empty()) {
      spdlog::info("加载本地凭据 ({} 字节)...", sealed_data.size());

      // 尝试解密
      bool service_error = false;
      auto data = client.unseal_data(sealed_data, &service_error);

      if (data.empty()) {
        if (service_error) {
          // 服务不可用，重新连接
          spdlog::warn("TPM 服务不可用，重新连接...");
          client.disconnect();
          continue;
        }
        // 解密失败但服务正常，可能是明文数据
        spdlog::info("数据非 TPM 加密格式，直接加载...");
        data = sealed_data;
      }

      if (client.load_credentials(data)) {
        spdlog::info("凭据已上传到守护进程");
      } else {
        spdlog::warn("凭据上传失败");
      }
    } else {
      spdlog::info("没有本地凭据");
    }

    spdlog::info("等待验证请求...");
    spdlog::info("-----------------------------------");

    // 心跳检测参数
    constexpr int HEARTBEAT_INTERVAL_MS = 3000;  // 心跳间隔 3 秒
    constexpr int HEARTBEAT_FAIL_THRESHOLD = 3;  // 连续失败 3 次断开
    int heartbeat_fail_count = 0;
    auto last_heartbeat = std::chrono::steady_clock::now();

    // 运行事件循环
    while (g_running.load() && client.is_connected()) {
      client.run();

      // 心跳检测
      auto now = std::chrono::steady_clock::now();
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now - last_heartbeat)
                         .count();

      if (elapsed >= HEARTBEAT_INTERVAL_MS) {
        last_heartbeat = now;
        if (client.ping()) {
          heartbeat_fail_count = 0;
        } else {
          heartbeat_fail_count++;
          spdlog::warn("心跳检测失败 ({}/{})", heartbeat_fail_count,
                       HEARTBEAT_FAIL_THRESHOLD);
          if (heartbeat_fail_count >= HEARTBEAT_FAIL_THRESHOLD) {
            spdlog::error("Daemon 无响应，断开连接并重试...");
            break;
          }
        }
      }
    }

    client.disconnect();
    if (g_running.load()) {
      spdlog::warn("与守护进程断开连接，尝试重连...");
    }
  }

  spdlog::info("-----------------------------------");
  spdlog::info("客户端已退出");

  return 0;
}
