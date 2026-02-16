#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "config.h"

// 设置日志级别为 debug 以便调试
static struct LogInitializer {
  LogInitializer() { spdlog::set_level(spdlog::level::debug); }
} log_init;

using namespace howdy;

class ConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir = std::filesystem::temp_directory_path() / "howdy_test_config";
    std::filesystem::create_directories(test_dir);
  }

  void TearDown() override {
    if (std::filesystem::exists(test_dir)) {
      std::filesystem::remove_all(test_dir);
    }
  }

  std::filesystem::path create_test_config(const std::string& content) {
    auto config_path = test_dir / "test_config.conf";
    std::ofstream file(config_path);
    file << content;
    file.close();
    return config_path;
  }

  std::filesystem::path test_dir;
};

// ── Policy Parsing ───────────────────────────────────────────

TEST_F(ConfigTest, ParsePolicy_AlwaysRespond) {
  auto policy = Config::parse_policy("always_respond");
  EXPECT_EQ(policy, DevicePolicy::ALWAYS_RESPOND);
}

TEST_F(ConfigTest, ParsePolicy_Fallback) {
  auto policy = Config::parse_policy("fallback");
  EXPECT_EQ(policy, DevicePolicy::FALLBACK);
}

TEST_F(ConfigTest, ParsePolicy_BackwardCompatible_SilentFallback) {
  auto policy = Config::parse_policy("silent_fallback");
  EXPECT_EQ(policy, DevicePolicy::FALLBACK);
}

TEST_F(ConfigTest, ParsePolicy_BackwardCompatible_PreferHardware) {
  auto policy = Config::parse_policy("prefer_hardware");
  EXPECT_EQ(policy, DevicePolicy::FALLBACK);
}

TEST_F(ConfigTest, ParsePolicy_CaseInsensitive) {
  EXPECT_EQ(Config::parse_policy("ALWAYS_RESPOND"),
            DevicePolicy::ALWAYS_RESPOND);
  EXPECT_EQ(Config::parse_policy("Fallback"), DevicePolicy::FALLBACK);
  EXPECT_EQ(Config::parse_policy("FALLBACK"), DevicePolicy::FALLBACK);
}

TEST_F(ConfigTest, ParsePolicy_InvalidDefault) {
  auto policy = Config::parse_policy("invalid_policy");
  EXPECT_EQ(policy, DevicePolicy::FALLBACK);
}

// ── Policy to String ─────────────────────────────────────────

TEST_F(ConfigTest, PolicyToString_AllValues) {
  EXPECT_EQ(Config::policy_to_string(DevicePolicy::ALWAYS_RESPOND),
            "always_respond");
  EXPECT_EQ(Config::policy_to_string(DevicePolicy::FALLBACK), "fallback");
}

// ── Config Loading ───────────────────────────────────────────

TEST_F(ConfigTest, LoadConfig_ValidFile) {
  auto config_path = create_test_config(R"(
device_policy = fallback
pam_service = test_service
verification_timeout = 60
debug_logging = true
)");

  auto config = Config::load(config_path.string());
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->device_policy, DevicePolicy::FALLBACK);
  EXPECT_EQ(config->pam_service, "test_service");
  EXPECT_EQ(config->verification_timeout, 60);
  EXPECT_TRUE(config->debug_logging);
}

TEST_F(ConfigTest, LoadConfig_DefaultValues) {
  auto config_path = create_test_config("");

  auto config = Config::load(config_path.string());
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->device_policy, DevicePolicy::FALLBACK);
  EXPECT_EQ(config->pam_service, "howdy-fido2");
  EXPECT_EQ(config->verification_timeout, 30);
  EXPECT_FALSE(config->debug_logging);
}

TEST_F(ConfigTest, LoadConfig_WithComments) {
  auto config_path = create_test_config(R"(
# This is a comment
device_policy = always_respond  # inline comment
# Another comment
pam_service = my_service
)");

  auto config = Config::load(config_path.string());
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->device_policy, DevicePolicy::ALWAYS_RESPOND);
  EXPECT_EQ(config->pam_service, "my_service");
}

TEST_F(ConfigTest, LoadConfig_WithWhitespace) {
  auto config_path = create_test_config(R"(
  device_policy   =   fallback  
  pam_service=test
)");

  auto config = Config::load(config_path.string());
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->device_policy, DevicePolicy::FALLBACK);
  EXPECT_EQ(config->pam_service, "test");
}

TEST_F(ConfigTest, LoadConfig_EmptyLines) {
  auto config_path = create_test_config(R"(

device_policy = always_respond

pam_service = test

)");

  auto config = Config::load(config_path.string());
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->device_policy, DevicePolicy::ALWAYS_RESPOND);
  EXPECT_EQ(config->pam_service, "test");
}

TEST_F(ConfigTest, LoadConfig_DebugLoggingVariants) {
  auto test_config = [this](const std::string& value, bool expected) {
    auto config_path = create_test_config("debug_logging = " + value);
    auto config = Config::load(config_path.string());
    ASSERT_TRUE(config.has_value());
    EXPECT_EQ(config->debug_logging, expected);
  };

  test_config("true", true);
  test_config("1", true);
  test_config("yes", true);
  test_config("false", false);
  test_config("0", false);
  test_config("no", false);
}

TEST_F(ConfigTest, LoadConfig_InvalidTimeout) {
  auto config_path = create_test_config(R"(
verification_timeout = not_a_number
)");

  auto config = Config::load(config_path.string());
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->verification_timeout, 30);  // Should use default
}

TEST_F(ConfigTest, LoadConfig_NonexistentFile) {
  auto config = Config::load("/nonexistent/config.conf");
  ASSERT_TRUE(config.has_value());  // Returns default config
  EXPECT_EQ(config->device_policy, DevicePolicy::FALLBACK);
}

TEST_F(ConfigTest, LoadConfig_PartialConfig) {
  auto config_path = create_test_config(R"(
device_policy = fallback
)");

  auto config = Config::load(config_path.string());
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->device_policy, DevicePolicy::FALLBACK);
  EXPECT_EQ(config->pam_service, "howdy-fido2");  // Default
  EXPECT_EQ(config->verification_timeout, 30);    // Default
}

TEST_F(ConfigTest, LoadConfig_UnknownKeys) {
  auto config_path = create_test_config(R"(
device_policy = always_respond
unknown_key = some_value
pam_service = test
)");

  auto config = Config::load(config_path.string());
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->device_policy, DevicePolicy::ALWAYS_RESPOND);
  EXPECT_EQ(config->pam_service, "test");
}

TEST_F(ConfigTest, LoadConfig_InvalidFormat) {
  auto config_path = create_test_config(R"(
device_policy = always_respond
invalid line without equals sign
pam_service = test
)");

  auto config = Config::load(config_path.string());
  ASSERT_TRUE(config.has_value());
  EXPECT_EQ(config->device_policy, DevicePolicy::ALWAYS_RESPOND);
  EXPECT_EQ(config->pam_service, "test");
}
