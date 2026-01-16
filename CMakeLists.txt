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

# 源文件
set(SOURCES
    src/uhid_device.cpp
    src/fido2_device.cpp
    src/pam_auth.cpp
    src/crypto.cpp
    src/cbor_helper.cpp
    src/tpm_storage.cpp
)

# 头文件目录
include_directories(include ${PAM_INCLUDE_DIR} ${CBOR_INCLUDE_DIR} ${TSS2_INCLUDE_DIRS})

# 创建库
add_library(howdy_fido2_lib STATIC ${SOURCES})
target_include_directories(howdy_fido2_lib PUBLIC include)
target_link_libraries(howdy_fido2_lib PUBLIC 
    ${PAM_LIBRARY} 
    ${CBOR_LIBRARY} 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    spdlog::spdlog
    ${TSS2_LIBRARIES}
)

# 主程序
add_executable(howdy-fido2 src/main.cpp)
target_link_libraries(howdy-fido2 PRIVATE howdy_fido2_lib pthread)

# 安装规则
install(TARGETS howdy-fido2 DESTINATION bin)
install(FILES pam.d/howdy-fido2 DESTINATION /etc/pam.d OPTIONAL)

# 打印构建信息
message(STATUS "Project: ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "PAM Library: ${PAM_LIBRARY}")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")