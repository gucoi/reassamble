cmake_minimum_required(VERSION 3.10)
project(c_capture C)

# 设置 C 标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 使用 pkg-config 查找 libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# 添加头文件目录
include_directories(${PCAP_INCLUDE_DIRS} include)

# 添加源文件
set(SOURCES
    src/capture.c
    src/backends/pcap_backend.c
)

# 创建共享库和静态库
add_library(capture SHARED ${SOURCES})
add_library(capture_static STATIC ${SOURCES})
set_target_properties(capture_static PROPERTIES OUTPUT_NAME capture)

# 链接 libpcap
target_link_libraries(capture ${PCAP_LIBRARIES})
target_link_libraries(capture_static ${PCAP_LIBRARIES})

# 设置输出目录
set_target_properties(capture capture_static PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# 安装规则
install(TARGETS capture capture_static
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include/c_capture
    FILES_MATCHING PATTERN "*.h"
) 