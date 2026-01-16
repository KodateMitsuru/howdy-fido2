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

# 核心库源文件（不含 main）
set(CORE_SOURCES
    src/uhid_device.cpp
    src/fido2_device.cpp
    src/pam_auth.cpp
    src/crypto.cpp
    src/cbor_helper.cpp
    src/tpm_storage.cpp
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

install(TARGETS howdy-fido2-daemon howdy-fido2-client DESTINATION bin)

# 打印构建信息
message(STATUS "Project: ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "PAM Library: ${PAM_LIBRARY}")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "sdbus-c++ Version: ${SDBUS_VERSION}")