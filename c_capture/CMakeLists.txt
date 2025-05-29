cmake_minimum_required(VERSION 3.10)
project(capture C)

# 设置 C 标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 查找 libpcap
find_package(PCAP REQUIRED)

# 添加头文件目录
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# 添加源文件
set(SOURCES
    src/capture.c
    src/backends/pcap_backend.c
)

# 创建共享库
add_library(capture SHARED ${SOURCES})

# 链接 libpcap
target_link_libraries(capture ${PCAP_LIBRARIES})

# 设置输出目录
set_target_properties(capture PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# 安装规则
install(TARGETS capture
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/
    DESTINATION include/capture
    FILES_MATCHING PATTERN "*.h"
) 