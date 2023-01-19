cmake_minimum_required(VERSION 3.10)
project(wasm-demo)

set(CMAKE_CXX_STANDARD 17)

SET(BPF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../bpf-loader/)
include_directories(${BPF_DIR}/include/)    # search for eunomia headers
link_directories(${BPF_DIR}/build/lib/Release/)     # search for libeunomia.a
link_directories(${BPF_DIR}/build/libbpf/)      # search for libbpf.a

SET(EWASM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../wasm-runtime/)
include_directories(${EWASM_DIR}/include/)  # search ewasm headers
link_directories(${EWASM_DIR}/build/lib/Release)    # search libewasm.a
link_directories(${EWASM_DIR}/build/)   # search for libvmlib.a

SET(IWASM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/wasm-micro-runtime/core/iwasm)
include_directories(${IWASM_DIR}/include/)  # search for wasm_export.h

add_executable(main main.cpp)
target_link_libraries(main  libewasm.a  libeunomia.a libvmlib.a libbpf.a elf z)