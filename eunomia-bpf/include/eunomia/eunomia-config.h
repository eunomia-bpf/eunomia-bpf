#ifndef EUNOMIA_CONFIG_H_
#define EUNOMIA_CONFIG_H_

#include <string>

/// Global config to control the behavior of eunomia-bpf
struct eunomia_config {
    /// perf buffer related config
    std::size_t perf_buffer_pages = 64;
    std::size_t perf_buffer_time_ms = 10;

    // poll config
    int poll_timeout_ms = 100;
};

#endif