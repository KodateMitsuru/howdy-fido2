/**
 * howdy-fido2-passkey - Passkey 管理工具
 *
 * 用于管理本地存储的 FIDO2 凭据
 */

#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <unistd.h>

#include <argparse/argparse.hpp>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <print>
#include <string>
#include <vector>

#include "dbus_interface.h"
#include "tpm_storage.h"

namespace fs = std::filesystem;

// 凭据文件路径
std::string get_credentials_path() {
  const char* home = getenv("HOME");
  if (!home) return "";
  return std::string(home) + "/.local/share/howdy-fido2/credentials.sealed";
}

// 读取凭据文件
std::vector<uint8_t> read_credentials_file() {
  std::string path = get_credentials_path();
  if (path.empty() || !fs::exists(path)) {
    return {};
  }

  std::ifstream file(path, std::ios::binary);
  if (!file) return {};

  file.seekg(0, std::ios::end);
  size_t size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> data(size);
  file.read(reinterpret_cast<char*>(data.data()), size);
  return data;
}

// 保存凭据文件
bool save_credentials_file(const std::vector<uint8_t>& data) {
  std::string path = get_credentials_path();
  if (path.empty()) return false;

  // 确保目录存在
  fs::path dir = fs::path(path).parent_path();
  if (!fs::exists(dir)) {
    fs::create_directories(dir);
    chmod(dir.c_str(), 0700);
  }

  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) return false;

  file.write(reinterpret_cast<const char*>(data.data()), data.size());
  chmod(path.c_str(), 0600);
  return true;
}

// 将字节数组转为十六进制字符串
std::string to_hex(const std::vector<uint8_t>& data, size_t max_len = 0) {
  std::string result;
  size_t len = max_len > 0 ? std::min(data.size(), max_len) : data.size();
  for (size_t i = 0; i < len; i++) {
    std::format_to(std::back_inserter(result), "{:02x}", data[i]);
  }
  if (max_len > 0 && data.size() > max_len) {
    result += "...";
  }
  return result;
}

int cmd_info() {
  std::string path = get_credentials_path();
  std::print("凭据文件路径: {}\n", path);

  if (!fs::exists(path)) {
    std::print("文件状态: 不存在\n");
  } else {
    auto file_size = fs::file_size(path);
    std::print("文件状态: 存在 ({} 字节)\n", file_size);
  }

  // 检查 daemon 连接
  howdy::DBusClient client;
  if (client.connect() && client.is_service_ready()) {
    std::print("Daemon 状态: 已就绪\n");
    std::print("TPM 加密: 可用\n");
    client.disconnect();
  } else {
    std::print("Daemon 状态: 未运行\n");
    std::print("TPM 加密: 不可用\n");
  }

  return 0;
}

int cmd_list(howdy::DBusClient& client) {
  auto sealed_data = read_credentials_file();
  if (sealed_data.empty()) {
    std::print("没有存储的 passkey\n");
    return 0;
  }

  // 解密
  auto data = client.unseal_data(sealed_data);
  if (data.empty()) {
    // 可能是明文存储
    data = sealed_data;
  }

  auto credentials = howdy::CredentialSerializer::deserialize(data);
  if (credentials.empty()) {
    std::print("没有存储的 passkey\n");
    return 0;
  }

  std::print("共 {} 个 passkey:\n\n", credentials.size());
  std::print("{:>4}  {:<30}  {:<20}  {:>8}\n", "序号", "网站 (RP ID)", "用户名",
             "计数器");
  std::print("{:-<4}  {:-<30}  {:-<20}  {:-<8}\n", "", "", "", "");

  int index = 1;
  for (const auto& cred : credentials) {
    std::string rp_display = cred.rp_id;
    if (rp_display.length() > 28) {
      rp_display = std::format("{}...", rp_display.substr(0, 25));
    }
    std::string user_display = cred.user_name;
    if (user_display.length() > 18) {
      user_display = std::format("{}...", user_display.substr(0, 15));
    }
    std::print("{:>4}  {:<30}  {:<20}  {:>8}\n", index++, rp_display,
               user_display, cred.counter);
  }

  return 0;
}

int cmd_show(howdy::DBusClient& client, int index) {
  auto sealed_data = read_credentials_file();
  if (sealed_data.empty()) {
    std::print(stderr, "错误: 没有存储的 passkey\n");
    return 1;
  }

  auto data = client.unseal_data(sealed_data);
  if (data.empty()) {
    data = sealed_data;
  }

  auto credentials = howdy::CredentialSerializer::deserialize(data);
  if (index < 1 || index > static_cast<int>(credentials.size())) {
    std::print(stderr, "错误: 无效的序号 {} (有效范围: 1-{})\n", index,
               credentials.size());
    return 1;
  }

  const auto& cred = credentials[index - 1];

  std::print("Passkey #{} 详细信息\n", index);
  std::print("{:=<50}\n", "");
  std::print("网站 (RP ID):    {}\n", cred.rp_id);
  std::print("用户名:          {}\n", cred.user_name);
  std::print("用户 ID:         {}\n", to_hex(cred.user_id, 16));
  std::print("凭据 ID:         {}\n", to_hex(cred.credential_id, 16));
  std::print("签名计数器:      {}\n", cred.counter);
  std::print("私钥长度:        {} 字节\n", cred.private_key.size());
  std::print("App ID Hash:     {}\n", to_hex(cred.app_id, 16));

  return 0;
}

int cmd_delete(howdy::DBusClient& client, int index, bool skip_confirm) {
  auto sealed_data = read_credentials_file();
  if (sealed_data.empty()) {
    std::print(stderr, "错误: 没有存储的 passkey\n");
    return 1;
  }

  auto data = client.unseal_data(sealed_data);
  if (data.empty()) {
    data = sealed_data;
  }

  auto credentials = howdy::CredentialSerializer::deserialize(data);
  if (index < 1 || index > static_cast<int>(credentials.size())) {
    std::print(stderr, "错误: 无效的序号 {} (有效范围: 1-{})\n", index,
               credentials.size());
    return 1;
  }

  const auto& cred = credentials[index - 1];

  if (!skip_confirm) {
    std::print("将要删除以下 passkey:\n");
    std::print("  网站: {}\n", cred.rp_id);
    std::print("  用户: {}\n", cred.user_name);
    std::print("\n确定要删除吗? [y/N] ");
    std::string response;
    std::getline(std::cin, response);
    if (response != "y" && response != "Y") {
      std::print("已取消\n");
      return 0;
    }
  }

  // 删除凭据
  credentials.erase(credentials.begin() + index - 1);

  // 重新序列化并保存
  auto new_data = howdy::CredentialSerializer::serialize(credentials);

  // 重新加密
  auto new_sealed = client.seal_data(new_data);
  if (new_sealed.empty()) {
    // TPM 不可用，明文保存
    new_sealed = new_data;
  }

  if (!save_credentials_file(new_sealed)) {
    std::print(stderr, "错误: 无法保存凭据文件\n");
    return 1;
  }

  // 通知 daemon 重新加载
  client.load_credentials(new_data);

  std::print("已删除 passkey: {} ({})\n", cred.rp_id, cred.user_name);
  return 0;
}

int cmd_clear(howdy::DBusClient& client, bool skip_confirm) {
  auto sealed_data = read_credentials_file();
  if (sealed_data.empty()) {
    std::print("没有存储的 passkey\n");
    return 0;
  }

  auto data = client.unseal_data(sealed_data);
  if (data.empty()) {
    data = sealed_data;
  }

  auto credentials = howdy::CredentialSerializer::deserialize(data);
  if (credentials.empty()) {
    std::print("没有存储的 passkey\n");
    return 0;
  }

  if (!skip_confirm) {
    std::print("将要删除所有 {} 个 passkey!\n", credentials.size());
    std::print("此操作不可恢复!\n\n");
    std::print("确定要继续吗? 请输入 'DELETE' 确认: ");
    std::string response;
    std::getline(std::cin, response);
    if (response != "DELETE") {
      std::print("已取消\n");
      return 0;
    }
  }

  // 删除文件
  std::string path = get_credentials_path();
  if (unlink(path.c_str()) != 0) {
    std::print(stderr, "错误: 无法删除凭据文件\n");
    return 1;
  }

  // 通知 daemon 清空凭据
  client.load_credentials({});

  std::print("已删除所有 {} 个 passkey\n", credentials.size());
  return 0;
}

int main(int argc, char* argv[]) {
  spdlog::set_level(spdlog::level::off);

  argparse::ArgumentParser program("howdy-fido2");
  program.add_description("用于管理本地存储的 FIDO2 凭据");

  // 全局选项
  program.add_argument("-y", "--yes")
      .help("跳过确认提示")
      .default_value(false)
      .implicit_value(true);

  // 子命令
  argparse::ArgumentParser list_cmd("list");
  list_cmd.add_description("列出所有存储的 passkey");

  argparse::ArgumentParser show_cmd("show");
  show_cmd.add_description("显示指定 passkey 的详细信息");
  show_cmd.add_argument("index").help("passkey 序号").scan<'i', int>();

  argparse::ArgumentParser delete_cmd("delete");
  delete_cmd.add_description("删除指定的 passkey");
  delete_cmd.add_argument("index")
      .help("要删除的 passkey 序号")
      .scan<'i', int>();

  argparse::ArgumentParser clear_cmd("clear");
  clear_cmd.add_description("清除所有 passkey（需确认）");

  argparse::ArgumentParser info_cmd("info");
  info_cmd.add_description("显示存储信息");

  // 添加子命令
  program.add_subparser(list_cmd);
  program.add_subparser(show_cmd);
  program.add_subparser(delete_cmd);
  program.add_subparser(clear_cmd);
  program.add_subparser(info_cmd);

  // 解析参数
  try {
    program.parse_args(argc, argv);
  } catch (const std::exception& err) {
    std::print(stderr, "错误: {}\n", err.what());
    std::print(stderr, "\n{}", program.help().str());
    return 1;
  }

  bool skip_confirm = program.get<bool>("--yes");

  // 处理子命令
  if (program.is_subcommand_used("info")) {
    return cmd_info();
  }

  // 其他命令需要连接 daemon
  howdy::DBusClient client;
  bool connected = client.connect() && client.is_service_ready();

  if (program.is_subcommand_used("list")) {
    if (!connected) {
      std::print("警告: daemon 服务未就绪，尝试直接读取...\n\n");
    }
    return cmd_list(client);
  }

  if (program.is_subcommand_used("show")) {
    if (!connected) {
      std::print("警告: daemon 服务未就绪，尝试直接读取...\n\n");
    }
    int index = show_cmd.get<int>("index");
    return cmd_show(client, index);
  }

  if (program.is_subcommand_used("delete")) {
    if (!connected) {
      std::print(stderr, "错误: daemon 服务未就绪\n");
      std::print(stderr, "请确保 howdy-fido2-daemon 正在运行\n");
      return 1;
    }
    int index = delete_cmd.get<int>("index");
    return cmd_delete(client, index, skip_confirm);
  }

  if (program.is_subcommand_used("clear")) {
    if (!connected) {
      std::print(stderr, "错误: daemon 服务未就绪\n");
      std::print(stderr, "请确保 howdy-fido2-daemon 正在运行\n");
      return 1;
    }
    return cmd_clear(client, skip_confirm);
  }

  // 如果没有指定子命令，显示帮助
  std::print(stderr, "{}", program.help().str());
  return 1;
}
