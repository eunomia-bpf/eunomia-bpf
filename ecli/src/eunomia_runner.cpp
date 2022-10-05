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

void
eunomia_program_runner::run_ebpf_program()
{
    std::string program_data =
        std::string(current_config.program_data_buffer.begin(),
                    current_config.program_data_buffer.end());
    if (program.load_json_config(program_data) < 0) {
        spdlog::error("load json config failed");
        return;
    }
    if (program.run() < 0) {
        spdlog::error("start ebpf program failed");
        return;
    }
    if (program.wait_and_poll_to_handler(current_config.export_format, nullptr)
        < 0) {
        spdlog::error("wait and print ebpf program failed");
        return;
    }
}

void
ewasm_program_runner::run_ebpf_program()
{
    ewasm_program p;
    std::string json_env = "{}";
    p.start(current_config.program_data_buffer, json_env);
}