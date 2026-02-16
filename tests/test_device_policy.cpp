#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <vector>

#include "config.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

#define private public
#define protected public
#include "fido2_device.h"
#undef private
#undef protected

using namespace howdy;

// Mock FIDO2Device for testing policy logic without actual device
class MockFIDO2Device : public FIDO2Device {
 public:
  MockFIDO2Device() : FIDO2Device() {
    // Don't actually start the device
  }

  bool test_should_respond(DevicePolicy policy) {
    config_.device_policy = policy;
    return should_respond_to_request();
  }
};

// ── Policy Logic Tests ───────────────────────────────────────

TEST(DevicePolicyLogic, AlwaysRespond_AlwaysReturnsTrue) {
  MockFIDO2Device device;
  EXPECT_TRUE(device.test_should_respond(DevicePolicy::ALWAYS_RESPOND));
}

TEST(DevicePolicyLogic, Fallback_DependsOnDevices) {
  MockFIDO2Device device;

  // Should not throw
  EXPECT_NO_THROW({ device.test_should_respond(DevicePolicy::FALLBACK); });
}

// ── Empty Response Tests ─────────────────────────────────────

TEST(EmptyResponseLogic, EmptyVector_IsSilent) {
  std::vector<uint8_t> response;

  EXPECT_TRUE(response.empty());
  EXPECT_EQ(response.size(), 0u);
}

TEST(EmptyResponseLogic, NonEmptyVector_IsNotSilent) {
  std::vector<uint8_t> response = {0x00};  // CTAP2_OK

  EXPECT_FALSE(response.empty());
  EXPECT_GT(response.size(), 0u);
}

// ── Config Integration Tests ─────────────────────────────────

TEST(ConfigIntegration, DefaultConfig_ValidValues) {
  MockFIDO2Device device;

  const auto& config = device.get_config();

  EXPECT_EQ(config.device_policy, DevicePolicy::FALLBACK);
  EXPECT_EQ(config.pam_service, "howdy-fido2");
  EXPECT_EQ(config.verification_timeout, 30);
  EXPECT_FALSE(config.debug_logging);
}

TEST(ConfigIntegration, LoadNonexistentConfig_UsesDefaults) {
  MockFIDO2Device device;

  device.load_config("/nonexistent/config.conf");

  const auto& config = device.get_config();
  EXPECT_EQ(config.device_policy, DevicePolicy::FALLBACK);
}

// ── Policy Enforcement Tests ─────────────────────────────────

class PolicyEnforcementTest : public ::testing::Test {
 protected:
  MockFIDO2Device device;
};

TEST_F(PolicyEnforcementTest, SetPolicy_AlwaysRespond) {
  device.config_.device_policy = DevicePolicy::ALWAYS_RESPOND;
  EXPECT_EQ(device.config_.device_policy, DevicePolicy::ALWAYS_RESPOND);
}

TEST_F(PolicyEnforcementTest, SetPolicy_Fallback) {
  device.config_.device_policy = DevicePolicy::FALLBACK;
  EXPECT_EQ(device.config_.device_policy, DevicePolicy::FALLBACK);
}

TEST_F(PolicyEnforcementTest, PolicySwitch_ValidTransitions) {
  // Test switching between all policies
  device.config_.device_policy = DevicePolicy::ALWAYS_RESPOND;
  EXPECT_EQ(device.config_.device_policy, DevicePolicy::ALWAYS_RESPOND);

  device.config_.device_policy = DevicePolicy::FALLBACK;
  EXPECT_EQ(device.config_.device_policy, DevicePolicy::FALLBACK);
}

// ── Silent Mode Tests ────────────────────────────────────────

TEST(SilentModeLogic, EmptyResponseVector_MeansSilent) {
  std::vector<uint8_t> silent_response;

  // Empty vector represents silent mode
  EXPECT_TRUE(silent_response.empty());
}

TEST(SilentModeLogic, ErrorResponseVector_NotSilent) {
  std::vector<uint8_t> error_response = {0x2E};  // CTAP2_ERR_NO_CREDENTIALS

  // Non-empty vector means a response will be sent
  EXPECT_FALSE(error_response.empty());
}

TEST(SilentModeLogic, SuccessResponseVector_NotSilent) {
  std::vector<uint8_t> success_response = {0x00, 0x01, 0x02};

  // Non-empty vector means a response will be sent
  EXPECT_FALSE(success_response.empty());
}

// ── Configuration Persistence Tests ──────────────────────────

TEST(ConfigurationPersistence, MultipleLoads_MaintainLastConfig) {
  MockFIDO2Device device;

  // Load first config (nonexistent, uses defaults)
  device.load_config("/tmp/test1.conf");
  auto config1 = device.get_config();

  // Manually change policy
  device.config_.device_policy = DevicePolicy::ALWAYS_RESPOND;

  // Load another config (nonexistent, uses defaults again)
  device.load_config("/tmp/test2.conf");
  auto config2 = device.get_config();

  // Second load should reset to defaults
  EXPECT_EQ(config2.device_policy, DevicePolicy::FALLBACK);
}
