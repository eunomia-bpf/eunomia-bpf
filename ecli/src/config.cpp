/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */

#include "ecli/config.h"

#include <json.hpp>
#include <iostream>
#include <fstream>

#define get_from_json_at(name)                                   \
    try {                                                        \
        j.at(#name).get_to(data.name);                           \
    } catch (...) {                                              \
        std::cerr << #name << " use default value" << std::endl; \
    }

static void
from_json(const nlohmann::json &j, program_config_data &data)
{
    get_from_json_at(url);
    get_from_json_at(program_data_buffer);
    get_from_json_at(args);
}

static void
from_json(const nlohmann::json &j, ecli_config_data &data)
{
    get_from_json_at(run_selected);
    get_from_json_at(enabled_trackers);
    get_from_json_at(server_host);
    get_from_json_at(server_port);
    get_from_json_at(exit_after);
}

ecli_config_data
ecli_config_data::from_json_file(const std::string &file_path)
{
    std::ifstream i(file_path);
    nlohmann::json j;
    i >> j;
    return j.get<ecli_config_data>();
}

program_config_data
program_config_data::from_json_str(const std::string &json_str)
{
    try {
        nlohmann::json j = nlohmann::json::parse(json_str);
        return j.get<program_config_data>();
    } catch (...) {
        std::cerr << "json parse error for tracker_config_data! " << json_str
                  << std::endl;
    }
    return program_config_data{};
}
