cmake_minimum_required(VERSION 3.16)
project(howdy-fido2 VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 查找依赖库
find_library(PAM_LIBRARY pam REQUIRED)
find_path(PAM_INCLUDE_DIR security/pam_appl.h REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(CBOR_LIBRARY cbor REQUIRED)
find_path(CBOR_INCLUDE_DIR cbor.h REQUIRED)
find_package(spdlog REQUIRED)

# TPM2 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(TSS2 REQUIRED tss2-esys tss2-mu)

# sdbus-c++ 库 (D-Bus IPC)
pkg_check_modules(SDBUS REQUIRED sdbus-c++)

# libfido2 库 (FIDO2 设备检测)
pkg_check_modules(LIBFIDO2 REQUIRED libfido2)

# 核心库源文件（不含 main）
set(CORE_SOURCES
    src/uhid_device.cpp
    src/fido2_device.cpp
    src/pam_auth.cpp
    src/crypto.cpp
    src/cbor_helper.cpp
    src/tpm_storage.cpp
    src/config.cpp
    src/device_detector.cpp
)

# D-Bus 接口源文件
set(DBUS_SOURCES
    src/dbus_interface.cpp
)

# 头文件目录
include_directories(
    include 
    ${PAM_INCLUDE_DIR} 
    ${CBOR_INCLUDE_DIR} 
    ${TSS2_INCLUDE_DIRS}
    ${SDBUS_INCLUDE_DIRS}
    ${LIBFIDO2_INCLUDE_DIRS}
)

# 创建核心库
add_library(howdy_fido2_core STATIC ${CORE_SOURCES})
target_include_directories(howdy_fido2_core PUBLIC include)
target_link_libraries(howdy_fido2_core PUBLIC 
    ${PAM_LIBRARY} 
    ${CBOR_LIBRARY} 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    spdlog::spdlog
    ${LIBFIDO2_LIBRARIES}
    ${TSS2_LIBRARIES}
)

# 创建 D-Bus 库
add_library(howdy_fido2_dbus STATIC ${DBUS_SOURCES})
target_include_directories(howdy_fido2_dbus PUBLIC include)
target_link_libraries(howdy_fido2_dbus PUBLIC 
    spdlog::spdlog
    ${SDBUS_LIBRARIES}
)

# 守护进程（高权限：UHID + TPM）
add_executable(howdy-fido2-daemon src/daemon_main.cpp)
target_link_libraries(howdy-fido2-daemon PRIVATE 
    howdy_fido2_core 
    howdy_fido2_dbus 
    pthread
)

# 客户端（低权限：PAM 验证）
add_executable(howdy-fido2-client src/client_main.cpp)
target_link_libraries(howdy-fido2-client PRIVATE 
    howdy_fido2_core
    howdy_fido2_dbus
    pthread
)

# Passkey 管理工具
add_executable(howdy-fido2-passkey src/passkey_tool.cpp)
target_link_libraries(howdy-fido2-passkey PRIVATE 
    howdy_fido2_core
    howdy_fido2_dbus
    pthread
)

install(TARGETS howdy-fido2-daemon howdy-fido2-client howdy-fido2-passkey DESTINATION bin)

# ── 测试 ───────────────────────────────────────────────────
option(BUILD_TESTS "Build unit / integration tests" ON)

if(BUILD_TESTS)
  enable_testing()
  find_package(GTest REQUIRED)
  include(GoogleTest)

  # 辅助宏：添加一个 test target
  function(howdy_add_test)
    cmake_parse_arguments(TEST "" "NAME" "SOURCES;LIBS" ${ARGN})
    add_executable(${TEST_NAME} ${TEST_SOURCES})
    target_link_libraries(${TEST_NAME} PRIVATE ${TEST_LIBS} GTest::gtest_main spdlog::spdlog)
    gtest_discover_tests(${TEST_NAME})
  endfunction()

  # Level 0 — 无特权
  howdy_add_test(NAME test_byte_utils
    SOURCES tests/test_byte_utils.cpp)

  howdy_add_test(NAME test_credential_serializer
    SOURCES tests/test_credential_serializer.cpp
    LIBS howdy_fido2_core)

  howdy_add_test(NAME test_crypto
    SOURCES tests/test_crypto.cpp
    LIBS howdy_fido2_core)

  howdy_add_test(NAME test_cbor
    SOURCES tests/test_cbor.cpp
    LIBS howdy_fido2_core)

  howdy_add_test(NAME test_config
    SOURCES tests/test_config.cpp
    LIBS howdy_fido2_core)

  howdy_add_test(NAME test_device_detector
    SOURCES tests/test_device_detector.cpp
    LIBS howdy_fido2_core)

  howdy_add_test(NAME test_device_policy
    SOURCES tests/test_device_policy.cpp
    LIBS howdy_fido2_core)

  # Level 1 — TPM 访问
  howdy_add_test(NAME test_tpm_storage
    SOURCES tests/test_tpm_storage.cpp
    LIBS howdy_fido2_core)

  # Level 2 — PAM
  howdy_add_test(NAME test_pam_auth
    SOURCES tests/test_pam_auth.cpp
    LIBS howdy_fido2_core)

  # Level 3 — root (UHID)
  howdy_add_test(NAME test_uhid_device
    SOURCES tests/test_uhid_device.cpp
    LIBS howdy_fido2_core pthread)

  howdy_add_test(NAME test_fido2_device
    SOURCES tests/test_fido2_device.cpp
    LIBS howdy_fido2_core pthread)

  # Level 2 — D-Bus 系统总线
  howdy_add_test(NAME test_dbus
    SOURCES tests/test_dbus.cpp
    LIBS howdy_fido2_core howdy_fido2_dbus pthread)

  # Level 4 — 全栈端到端
  howdy_add_test(NAME test_e2e
    SOURCES tests/test_e2e.cpp
    LIBS howdy_fido2_core howdy_fido2_dbus pthread)
endif()

# 打印构建信息
message(STATUS "Project: ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "PAM Library: ${PAM_LIBRARY}")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "sdbus-c++ Version: ${SDBUS_VERSION}")