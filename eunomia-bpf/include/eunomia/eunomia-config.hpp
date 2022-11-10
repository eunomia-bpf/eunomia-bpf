#ifndef EUNOMIA_CONFIG_HPP_
#define EUNOMIA_CONFIG_HPP_

#include <string>

/// Global config to control the behavior of eunomia-bpf
/// TODO: load config from json or config files
struct runner_config {
    /// Whether libbpf should print debug info
    /// This will only be apply to libbpf when start running
    bool libbpf_debug_verbose = false;

    /// @brief whether we should print the bpf_printk
    /// from /sys/kernel/debug/tracing/trace_pipe
    bool print_kernel_debug = false;
};

#endif