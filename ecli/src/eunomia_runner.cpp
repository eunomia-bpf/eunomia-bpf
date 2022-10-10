/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "ecli/eunomia_runner.h"

#include <spdlog/spdlog.h>

#include <json.hpp>

#include "eunomia/eunomia-bpf.h"

using json = nlohmann::json;

int
eunomia_program_runner::run_ebpf_program()
{
    std::string program_data =
        std::string(current_config.program_data_buffer.begin(),
                    current_config.program_data_buffer.end());
    if (program.load_json_config(program_data) < 0) {
        spdlog::error("load json config failed");
        return -1;
    }
    if (program.run() < 0) {
        spdlog::error("start ebpf program failed");
        return -1;
    }
    if (program.wait_and_poll_to_handler(current_config.export_format, nullptr)
        < 0) {
        spdlog::error("wait and print ebpf program failed");
        return -1;
    }
    return 0;
}

int
ewasm_program_runner::run_ebpf_program()
{
    ewasm_program p;
    std::string json_env = "[\"app\"]";
    if (current_config.args.size() > 0) {
        json j;
        j.push_back("app");
        for (auto &arg : current_config.args) {
            j.push_back(arg);
        }
        json_env = j.dump();
    }
    return p.start(current_config.program_data_buffer, json_env);
}