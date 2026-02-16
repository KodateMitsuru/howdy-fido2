#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include "uhid_device.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

using namespace howdy;

// ── Fixture: 需要 /dev/uhid (root) ──────────────────────────
class UHIDTest : public ::testing::Test {
 protected:
  UHIDDevice uhid{"GTest FIDO2 Device"};

  void SetUp() override {
    if (!uhid.create()) {
      GTEST_SKIP() << "Cannot open /dev/uhid — need root privileges";
    }
  }

  void TearDown() override { uhid.destroy(); }
};

// ── Create / Destroy 生命周期 ────────────────────────────────
TEST_F(UHIDTest, Create_Success) { EXPECT_TRUE(uhid.is_running()); }

TEST_F(UHIDTest, Destroy_StopsRunning) {
  uhid.destroy();
  EXPECT_FALSE(uhid.is_running());
}

TEST_F(UHIDTest, DoubleCreate_Idempotent) {
  // 已在 SetUp 中 create
  EXPECT_TRUE(uhid.create());  // 第二次也应该返回 true
  EXPECT_TRUE(uhid.is_running());
}

TEST_F(UHIDTest, DoubleDestroy_Safe) {
  uhid.destroy();
  uhid.destroy();  // 不应崩溃
  EXPECT_FALSE(uhid.is_running());
}

// ── send_input ───────────────────────────────────────────────
TEST_F(UHIDTest, SendInput_Succeeds) {
  std::vector<uint8_t> data(HID_REPORT_SIZE, 0x42);
  EXPECT_TRUE(uhid.send_input(data));
}

TEST_F(UHIDTest, SendInput_SmallData) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03};
  // 小于 HID_REPORT_SIZE 也应成功（内部会填充）
  EXPECT_TRUE(uhid.send_input(data));
}

// ── send_input after destroy ─────────────────────────────────
TEST(UHIDDeviceNoInit, SendInput_NotRunning) {
  UHIDDevice uhid;
  // 不调用 create()
  std::vector<uint8_t> data = {0x01};
  EXPECT_FALSE(uhid.send_input(data));
}

// ── Output handler 设置 ──────────────────────────────────────
TEST_F(UHIDTest, SetOutputHandler_NoThrow) {
  bool handler_called = false;
  uhid.set_output_handler(
      [&](const std::vector<uint8_t>& data) { handler_called = true; });
  // 给事件循环一点时间启动
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  // 仅验证设置不崩溃
}

// ── Create 后 is_running 稳定 ────────────────────────────────
TEST_F(UHIDTest, IsRunning_StableAfterCreate) {
  // 等待一小段时间确保事件循环已启动
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  EXPECT_TRUE(uhid.is_running());
}
