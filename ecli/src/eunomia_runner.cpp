/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "ecli/eunomia_runner.h"

#include <json.hpp>

#include "eunomia/eunomia-bpf.h"

using json = nlohmann::json;

int
eunomia_program_runner::load_and_attach_eunomia_skel()
{
    std::string program_data =
        std::string(current_config.program_data_buffer.begin(),
                    current_config.program_data_buffer.end());
    if (program.open_from_json_config(program_data) < 0) {
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