set(CMAKE_C_COMPILER /usr/bin/clang)
set(CMAKE_CXX_COMPILER /usr/bin/clang++)

cmake_minimum_required(VERSION 3.10)
project(callback)

set(PROJECT_NAME callback)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "-std=c++11 -DWASM_API_DEBUG   -Wall -ggdb -O -fsanitize=address ")
set(CMAKE_C_FLAGS "-DWASM_API_DEBUG   -Wall -ggdb -O -fsanitize=address")

set(WASM_C_API_DIR ${CMAKE_SOURCE_DIR}/../third_party/wasm-c-api)
set(EUNOMIA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../bpf-loader)

file(GLOB CPP_FILE ${CMAKE_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE V8_LIBS ${WASM_C_API_DIR}/v8/v8/out.gn/*.a)
file(GLOB WASM_OBJ_SET ${WASM_C_API_DIR}/out/*.o)

add_executable(${PROJECT_NAME} ${CPP_FILE})

include_directories(
        ${CMAKE_SOURCE_DIR}/include
        ${WASM_C_API_DIR}/v8/v8/include
        ${WASM_C_API_DIR}/include
        ${EUNOMIA_DIR}/include)

add_subdirectory(${EUNOMIA_DIR} ${CMAKE_CURRENT_BINARY_DIR}/eunomia)
add_dependencies(eunomia libbpf-build)
add_dependencies(${PROJECT_NAME} eunomia)
target_link_libraries(${PROJECT_NAME} ${WASM_OBJ_SET} ${V8_LIBS} ${V8_OBJS} eunomia dl pthread)