cmake_minimum_required(VERSION 3.30)
project(docker-proxy C)

set(CMAKE_C_STANDARD 11)
message(STATUS "Current architecture: ${CMAKE_SYSTEM_PROCESSOR}")

# 检测苹果系统
if(APPLE)
    add_definitions("-D__APPLE_INGORE_WARN")
endif()

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    add_definitions("-D__TARGET_ARCH_x86")
    SET(CMAKE_C_FLAGS,"${CMAKE_C_FLAGS} -target amd64-linux-gnu")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    add_definitions("-D__TARGET_ARCH_arm64")
    SET(CMAKE_C_FLAGS,"${CMAKE_C_FLAGS} -target arm64-linux-gnu")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    add_definitions("-D__TARGET_ARCH_arm64")
    SET(CMAKE_C_FLAGS,"${CMAKE_C_FLAGS} -target arm64-linux-gnu")
else ()
    message(STATUS "This is an unknown processor architecture.")
endif ()

include_directories("./ebpf/headers")

add_library(docker-proxy
        ebpf/tc-dns-parse.bpf.c
        ebpf/tc-dns-replace.bpf.c
        ebpf/tc-proxy.bpf.c
        ebpf/xdp-proxy.bpf.c
        ebpf/sk_lookup.bpf.c
)

