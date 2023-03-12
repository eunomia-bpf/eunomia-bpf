/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#ifndef EUNOMIA_MATA_DATA_
#define EUNOMIA_MATA_DATA_

#include <string>
#include <optional>
#include <vector>

namespace eunomia {

struct export_types_struct_member_meta {
    std::string name;
    std::string type;
};

struct export_types_struct_meta {
    std::vector<export_types_struct_member_meta> members;
    std::string name;
    uint32_t size;
    uint32_t type_id;

    void from_json_str(const std::string& j_str);
};

struct map_sample_meta {
    std::size_t interval;
    std::string type;
    // unit for print hist
    std::string unit = "(unit)";
    bool clear_map = true;
};

struct map_meta {
    std::string name;
    std::string ident;
    bool mmaped = false;
    std::optional<map_sample_meta> sample;

    std::string __raw_json_data;
};

struct prog_meta {
    std::string name;
    std::string attach;
    bool link;

    std::string __raw_json_data;
};

struct data_section_variable_meta {
    std::string name;
    std::string type;

    std::string __raw_json_data;
};

struct data_section_meta {
    std::string name;
    std::vector<data_section_variable_meta> variables;
};

struct bpf_skel_doc {
    std::string version;
    std::string brief;
    std::string details;
};

struct bpf_skel_meta {
    std::vector<data_section_meta> data_sections;
    std::vector<map_meta> maps;
    std::vector<prog_meta> progs;
    std::string obj_name;
    std::optional<bpf_skel_doc> doc;

    void from_json_str(const std::string& j_str);
};

/// global meta data config
struct eunomia_object_meta {
    bpf_skel_meta bpf_skel;
    std::vector<export_types_struct_meta> export_types;

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
    bool debug_verbose = false;

    std::string to_json_str();
    void from_json_str(const std::string& j_str);
};

/// Global config to control the behavior of eunomia-bpf
/// TODO: load config from json or config files
struct runner_config {
    /// @brief whether we should print the bpf_printk
    /// from /sys/kernel/debug/tracing/trace_pipe
    bool print_kernel_debug = false;
};

}  // namespace eunomia

#endif