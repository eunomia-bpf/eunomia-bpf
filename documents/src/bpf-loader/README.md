# bpf-loader: A Dynamic Loading Library for eBPF program

A wrapper of main functions of libbpf, some helper functions for user development.

- provide the ability to load ebpf code to the kernel and run it with a simple JSON.
- Use some additional data to help load and config the eBPF bytecode dynamically.
- multiple language bindings. We have `Rust/C/C++` now and will add more in the future.

## usage with cmake

cmake for example:

```cmake
set(EUNOMIA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../bpf-loader)
set(EUNOMIA_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/eunomia)
include_directories(${EUNOMIA_DIR}/include)
add_subdirectory(${EUNOMIA_DIR} ${CMAKE_CURRENT_BINARY_DIR}/eunomia)
add_dependencies(${PROJECT_NAME}_LIB eunomia_LIB)
add_dependencies(eunomia_LIB libbpf-build)
add_dependencies(${PROJECT_NAME} eunomia_LIB)
target_link_libraries(${PROJECT_NAME} PRIVATE eunomia_LIB)
```

see the example in [simple-runner](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/simple-runner) for more details.

## cli tool

a simple cli interface for bpf-loader library, which you can use it to start any eBPF program from a url in a command.

see [ecli](../ecli/index.md) for details.
