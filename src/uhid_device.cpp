#include "uhid_device.h"

#include <fcntl.h>
#include <linux/uhid.h>
#include <poll.h>
#include <spdlog/spdlog.h>
#include <unistd.h>

#include <cstring>

namespace howdy {

// FIDO2 HID 报告描述符
static const uint8_t FIDO2_REPORT_DESCRIPTOR[] = {
    0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance)
    0x09, 0x01,        // Usage (CTAPHID)
    0xA1, 0x01,        // Collection (Application)

    // 输入报告
    0x09, 0x20,        //   Usage (Input Report Data)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x81, 0x02,        //   Input (Data, Variable, Absolute)

    // 输出报告
    0x09, 0x21,        //   Usage (Output Report Data)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x91, 0x02,        //   Output (Data, Variable, Absolute)

    0xC0  // End Collection
};

UHIDDevice::UHIDDevice(const std::string& name) : device_name_(name) {}

UHIDDevice::~UHIDDevice() { destroy(); }

bool UHIDDevice::create() {
  if (running_.load()) {
    return true;
  }

  uhid_fd_ = open("/dev/uhid", O_RDWR | O_CLOEXEC);
  if (uhid_fd_ < 0) {
    spdlog::error("无法打开 /dev/uhid: {}", strerror(errno));
    spdlog::error("请检查 udev 规则或将用户加入相应组");
    return false;
  }

  // 创建 UHID 设备
  struct uhid_event ev{};
  ev.type = UHID_CREATE2;

  strncpy(reinterpret_cast<char*>(ev.u.create2.name), device_name_.c_str(),
          sizeof(ev.u.create2.name) - 1);

  // FIDO2 设备标准 VID/PID
  ev.u.create2.vendor = 0x1234;   // 自定义厂商ID
  ev.u.create2.product = 0xF1D0;  // FIDO相关产品ID
  ev.u.create2.version = 0x0100;
  ev.u.create2.bus = BUS_USB;
  ev.u.create2.country = 0;

  // 设置报告描述符
  memcpy(ev.u.create2.rd_data, FIDO2_REPORT_DESCRIPTOR,
         sizeof(FIDO2_REPORT_DESCRIPTOR));
  ev.u.create2.rd_size = sizeof(FIDO2_REPORT_DESCRIPTOR);

  ssize_t ret = write(uhid_fd_, &ev, sizeof(ev));
  if (ret < 0) {
    spdlog::error("创建 UHID 设备失败: {}", strerror(errno));
    close(uhid_fd_);
    uhid_fd_ = -1;
    return false;
  }

  running_.store(true);
  event_thread_ = std::thread(&UHIDDevice::event_loop, this);

  spdlog::info("FIDO2 虚拟设备创建成功: {}", device_name_);
  return true;
}

void UHIDDevice::destroy() {
  if (!running_.load()) {
    return;
  }

  running_.store(false);

  if (uhid_fd_ >= 0) {
    // 发送销毁事件
    struct uhid_event ev{};
    ev.type = UHID_DESTROY;
    write(uhid_fd_, &ev, sizeof(ev));
    close(uhid_fd_);
    uhid_fd_ = -1;
  }

  if (event_thread_.joinable()) {
    event_thread_.join();
  }

  spdlog::info("FIDO2 虚拟设备已销毁");
}

bool UHIDDevice::send_input(const std::vector<uint8_t>& data) {
  if (uhid_fd_ < 0 || !running_.load()) {
    return false;
  }

  struct uhid_event ev{};
  ev.type = UHID_INPUT2;
  ev.u.input2.size =
      std::min(data.size(), static_cast<size_t>(HID_REPORT_SIZE));
  memcpy(ev.u.input2.data, data.data(), ev.u.input2.size);

  ssize_t ret = write(uhid_fd_, &ev, sizeof(ev));
  return ret >= 0;
}

void UHIDDevice::event_loop() {
  struct pollfd pfd{};
  pfd.fd = uhid_fd_;
  pfd.events = POLLIN;

  while (running_.load()) {
    int ret = poll(&pfd, 1, 100);  // 100ms 超时
    if (ret < 0) {
      if (errno == EINTR) continue;
      spdlog::error("poll 错误: {}", strerror(errno));
      break;
    }

    if (ret > 0 && (pfd.revents & POLLIN)) {
      if (!handle_uhid_event()) {
        break;
      }
    }
  }
}

bool UHIDDevice::handle_uhid_event() {
  struct uhid_event ev{};
  ssize_t ret = read(uhid_fd_, &ev, sizeof(ev));

  if (ret < 0) {
    if (errno == EINTR || errno == EAGAIN) {
      return true;
    }
    spdlog::error("读取 UHID 事件失败: {}", strerror(errno));
    return false;
  }

  switch (ev.type) {
    case UHID_START:
      spdlog::debug("UHID: 设备已启动");
      break;

    case UHID_STOP:
      spdlog::debug("UHID: 设备已停止");
      break;

    case UHID_OPEN:
      spdlog::debug("UHID: 设备已打开");
      break;

    case UHID_CLOSE:
      spdlog::debug("UHID: 设备已关闭");
      break;

    case UHID_OUTPUT:
      // 收到主机发来的输出报告
      if (output_handler_) {
        std::vector<uint8_t> data(ev.u.output.data,
                                  ev.u.output.data + ev.u.output.size);
        output_handler_(data);
      }
      break;

    default:
      break;
  }

  return true;
}

}  // namespace howdy
