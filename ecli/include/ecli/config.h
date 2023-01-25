/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */

#ifndef ECLI_CONFIG_H
#define ECLI_CONFIG_H

#include <set>
#include <string>
#include <vector>
#include <eunomia/eunomia-bpf.h>

/// tracker config data
struct program_config_data {
    /// @brief  url of the program: path or http link
    std::string url;
    /// @brief  use cache or not
    bool use_cache;
    /// @brief program data buffer: wasm module or json
    std::vector<char> program_data_buffer;
    /// @brief  type of the program: wasm or json, of others
    enum class program_type { UNDEFINE, JSON_EUNOMIA, WASM_MODULE } prog_type;
    std::vector<std::string> args;
    /// export type format
    export_format_type export_format = export_format_type::EXPORT_PLANT_TEXT;

    static program_config_data from_json_str(const std::string &json_str);
};

/// config for eunomia

/// both config from toml and command line should be put here
struct ecli_config_data {
    /// global run mode
    std::string run_selected = "server";

    /// config for all enabled tracker
    std::vector<program_config_data> enabled_trackers = {};
    /// auto exit mode
    int exit_after = 0;

    /// parse config from json files
    static ecli_config_data from_json_file(const std::string &file_path);

    /// eunomia_http_server_port
    int server_port = 8527;
    /// eunomia_http_server_host
    std::string server_host = "localhost";
};

constexpr auto default_endpoint = "localhost:8527";
constexpr auto default_json_data_file_name = "package.json";
constexpr auto default_repo_base_url =
    "https://eunomia-bpf.github.io/eunomia-bpf/";
constexpr auto default_local_home_path = "/tmp/ebpm/";

constexpr auto remote_repo_base_env_var_name = "EUNOMIA_REPOSITORY";
constexpr auto local_home_env_var_name = "EUNOMIA_HOME";

#endif
