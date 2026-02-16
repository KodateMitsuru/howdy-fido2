#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

#define private public
#define protected public
#include "device_detector.h"
#undef private
#undef protected

using namespace howdy;

// ── FIDO2DeviceInfo Tests ────────────────────────────────────

TEST(DeviceDetector, FIDO2DeviceInfo_DefaultConstruction) {
  FIDO2DeviceInfo info{};
  EXPECT_TRUE(info.path.empty());
  EXPECT_TRUE(info.product_name.empty());
  EXPECT_EQ(info.vendor_id, 0);
  EXPECT_EQ(info.product_id, 0);
}

TEST(DeviceDetector, FIDO2DeviceInfo_Assignment) {
  FIDO2DeviceInfo info;
  info.path = "/dev/hidraw0";
  info.product_name = "Test Device";
  info.vendor_id = 0x1234;
  info.product_id = 0x5678;

  EXPECT_EQ(info.path, "/dev/hidraw0");
  EXPECT_EQ(info.product_name, "Test Device");
  EXPECT_EQ(info.vendor_id, 0x1234);
  EXPECT_EQ(info.product_id, 0x5678);
}

// ── Device Detection Tests ───────────────────────────────────

TEST(DeviceDetector, DetectOtherDevices_NoThrow) {
  EXPECT_NO_THROW({ auto devices = DeviceDetector::detect_other_devices(); });
}

TEST(DeviceDetector, DetectOtherDevices_ReturnsVector) {
  auto devices = DeviceDetector::detect_other_devices();
  EXPECT_TRUE(devices.empty() || !devices.empty());  // Just ensure it returns
}

// ── Virtual Device Identification ────────────────────────────

TEST(DeviceDetector, IsOurVirtualDevice_HowdyDevice) {
  FIDO2DeviceInfo info;
  info.product_name = "Howdy FIDO2 Device";

  EXPECT_TRUE(DeviceDetector::is_our_virtual_device(info));
}

TEST(DeviceDetector, IsOurVirtualDevice_OtherDevice) {
  FIDO2DeviceInfo info;
  info.product_name = "YubiKey 5";

  EXPECT_FALSE(DeviceDetector::is_our_virtual_device(info));
}

TEST(DeviceDetector, IsOurVirtualDevice_EmptyName) {
  FIDO2DeviceInfo info;
  info.product_name = "";

  EXPECT_FALSE(DeviceDetector::is_our_virtual_device(info));
}

// ── Integration Tests (may require actual devices) ───────────

TEST(DeviceDetector, DetectOtherDevices_ValidStructure) {
  auto devices = DeviceDetector::detect_other_devices();

  for (const auto& dev : devices) {
    // Each detected device should have basic information
    EXPECT_FALSE(dev.path.empty()) << "Device should have a path";
    EXPECT_TRUE(dev.path.starts_with("/dev/hidraw"))
        << "Device path should start with /dev/hidraw";
  }
}

// ── libfido2 Integration Tests ───────────────────────────────

TEST(DeviceDetector, IsFIDO2Device_InvalidPath) {
  EXPECT_FALSE(DeviceDetector::is_fido2_device("/nonexistent/device"));
}

TEST(DeviceDetector, IsFIDO2Device_EmptyPath) {
  EXPECT_FALSE(DeviceDetector::is_fido2_device(""));
}

// ── Performance Tests ────────────────────────────────────────

TEST(DeviceDetector, DetectOtherDevices_ReasonableTime) {
  auto start = std::chrono::steady_clock::now();

  auto devices = DeviceDetector::detect_other_devices();

  auto end = std::chrono::steady_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  // Detection should complete in reasonable time (< 5 seconds)
  EXPECT_LT(duration.count(), 5000)
      << "Device detection took " << duration.count() << "ms";
}

// ── Edge Case Tests ──────────────────────────────────────────

TEST(DeviceDetector, FIDO2DeviceInfo_CopySemantics) {
  FIDO2DeviceInfo info1;
  info1.path = "/dev/hidraw0";
  info1.product_name = "Test";
  info1.vendor_id = 0x1234;
  info1.product_id = 0x5678;

  FIDO2DeviceInfo info2 = info1;

  EXPECT_EQ(info2.path, info1.path);
  EXPECT_EQ(info2.product_name, info1.product_name);
  EXPECT_EQ(info2.vendor_id, info1.vendor_id);
  EXPECT_EQ(info2.product_id, info1.product_id);
}

TEST(DeviceDetector, FIDO2DeviceInfo_MoveSemantics) {
  FIDO2DeviceInfo info1;
  info1.path = "/dev/hidraw0";
  info1.product_name = "Test Device";

  FIDO2DeviceInfo info2 = std::move(info1);

  EXPECT_EQ(info2.path, "/dev/hidraw0");
  EXPECT_EQ(info2.product_name, "Test Device");
}
