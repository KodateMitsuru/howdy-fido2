#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace howdy {

// FIDO2 HID 报告描述符常量
constexpr uint16_t FIDO_USAGE_PAGE = 0xF1D0;
constexpr uint8_t FIDO_USAGE_CTAPHID = 0x01;
constexpr size_t HID_REPORT_SIZE = 64;

// CTAPHID 命令
enum class CTAPHIDCommand : uint8_t {
  MSG = 0x03,
  CBOR = 0x10,
  INIT = 0x06,
  PING = 0x01,
  CANCEL = 0x11,
  ERROR = 0x3F,
  KEEPALIVE = 0x3B,
  WINK = 0x08,
  LOCK = 0x04,
};

// CTAPHID 错误码
enum class CTAPHIDError : uint8_t {
  INVALID_CMD = 0x01,
  INVALID_PAR = 0x02,
  INVALID_LEN = 0x03,
  INVALID_SEQ = 0x04,
  MSG_TIMEOUT = 0x05,
  CHANNEL_BUSY = 0x06,
  LOCK_REQUIRED = 0x0A,
  INVALID_CHANNEL = 0x0B,
  OTHER = 0x7F,
};

// CTAPHID 初始化响应
struct CTAPHIDInitResponse {
  uint8_t nonce[8];
  uint32_t channel_id;
  uint8_t protocol_version;
  uint8_t device_major;
  uint8_t device_minor;
  uint8_t device_build;
  uint8_t capabilities;
};

class UHIDDevice {
 public:
  using OutputHandler = std::function<void(const std::vector<uint8_t>&)>;

  UHIDDevice(const std::string& name = "Howdy FIDO2 Device");
  ~UHIDDevice();

  // 禁止拷贝
  UHIDDevice(const UHIDDevice&) = delete;
  UHIDDevice& operator=(const UHIDDevice&) = delete;

  // 初始化和关闭
  bool create();
  void destroy();
  bool is_running() const { return running_.load(); }

  // 发送输入报告到主机
  bool send_input(const std::vector<uint8_t>& data);

  // 设置输出报告处理回调
  void set_output_handler(OutputHandler handler) {
    output_handler_ = std::move(handler);
  }

 private:
  void event_loop();
  bool handle_uhid_event();

  std::string device_name_;
  int uhid_fd_ = -1;
  std::atomic<bool> running_{false};
  std::thread event_thread_;
  OutputHandler output_handler_;
};

}  // namespace howdy
