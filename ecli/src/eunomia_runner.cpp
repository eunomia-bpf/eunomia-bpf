/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */

#include "ecli/eunomia_runner.h"

#include <json.hpp>

#include "eunomia/eunomia-bpf.hpp"

using json = nlohmann::json;

int
eunomia_program_runner::load_and_attach_eunomia_skel()
{
    std::string program_data =
        std::string(current_config.program_data_buffer.begin(),
                    current_config.program_data_buffer.end());
    json j = json::parse(program_data);
    json meta_config = j["meta"];
    std::string meta_config_str = meta_config.dump();
    std::string new_config;
    int res;

    if ((res = eunomia::parse_args_for_json_config(meta_config_str, new_config,
                                                   current_config.args))
        != 0) {
        return -1;
    }
    j["meta"] = json::parse(new_config);
    if (program.open_from_json_config(j.dump()) < 0) {
        std::cerr << "load json config failed" << std::endl;
        return -1;
    }
    if (program.load_and_attach() < 0) {
        std::cerr << "load and attach ebpf program failed" << std::endl;
        return -1;
    }
    if (program.wait_and_poll_to_handler(current_config.export_format, nullptr)
        < 0) {
        std::cerr << "wait and poll to handler failed" << std::endl;
        return -1;
    }
    return 0;
}

int
ewasm_program_runner::load_and_attach_eunomia_skel()
{
    ewasm_program p;
    std::string json_env = "[\"app\"]";
    json j;
    for (auto &arg : current_config.args) {
        j.push_back(arg);
    }
    json_env = j.dump();
    return p.start(current_config.program_data_buffer, json_env);
}