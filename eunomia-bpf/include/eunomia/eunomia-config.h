#ifndef EUNOMIA_CONFIG_H_
#define EUNOMIA_CONFIG_H_

#include <string>

/// Global config to control the behavior of eunomia-bpf
/// TODO: load config from json or config files
struct eunomia_config {
    /// perf buffer related config
    std::size_t perf_buffer_pages = 64;
    std::size_t perf_buffer_time_ms = 10;

    /// poll config
    int poll_timeout_ms = 100;

    /// print config
    /// print the types and names of export headers
    bool print_header = true;

    /// Whether libbpf should print debug info
    /// This will only be apply to libbpf when start running
    bool libbpf_debug_verbose = false;

    /// @brief whether we should print the bpf_printk
    /// from /sys/kernel/debug/tracing/trace_pipe
    bool print_kernel_debug = false;
};

#endif