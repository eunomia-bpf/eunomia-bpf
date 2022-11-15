/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include <clipp.h>

#include <json.hpp>
#include <string>
#include <vector>
#include <iostream>

#include "ecli/url_resolver.h"
#include "ecli/cmd_entry.h"

using namespace std::chrono_literals;
using json = nlohmann::json;

enum class eunomia_cmd_mode { run, help, pull };

int
main(int argc, char *argv[])
{
    ecli_config_data core_config;

    eunomia_cmd_mode cmd_selected = eunomia_cmd_mode::help;
    std::string log_level = "default";
    std::vector<std::string> run_with_extra_args;
    bool export_as_json;

    auto run_opt_cmd_args = clipp::opt_values("extra args", run_with_extra_args)
                            % "Some extra args provided to the ebpf program";

    auto cli =
        ((clipp::command("run").set(cmd_selected, eunomia_cmd_mode::run)
              % "run a ebpf program"
          | clipp::command("pull").set(cmd_selected, eunomia_cmd_mode::pull)
                % "pull a ebpf program from remote to local"
          | clipp::command("help").set(cmd_selected, eunomia_cmd_mode::help)),
         run_opt_cmd_args);

    if (!clipp::parse(argc, argv, cli)) {
        std::cout << clipp::make_man_page(cli, argv[0]);
        return 1;
    }

    switch (cmd_selected) {
        case eunomia_cmd_mode::run:
            return cmd_run_main(argc - 1, argv + 1);
        case eunomia_cmd_mode::pull:
            return cmd_pull_main(argc - 1, argv + 1);
        case eunomia_cmd_mode::help:
            std::cout << clipp::make_man_page(cli, argv[0]);
            break;
    }
    return 0;
}
