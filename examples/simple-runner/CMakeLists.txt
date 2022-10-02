cmake_minimum_required(VERSION 3.10)
project(eunomia-demo)

set(PROJECT_NAME demo)
set(CMAKE_BUILD_TYPE Release)
add_executable(${PROJECT_NAME} main.cpp)

set(EUNOMIA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../eunomia-bpf)
set(EUNOMIA_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/eunomia)
include_directories(${EUNOMIA_DIR}/include)

add_subdirectory(${EUNOMIA_DIR} ${CMAKE_CURRENT_BINARY_DIR}/eunomia)
add_dependencies(eunomia_LIB libbpf-build)
add_dependencies(${PROJECT_NAME} eunomia_LIB)
target_link_libraries(${PROJECT_NAME} eunomia_LIB)
