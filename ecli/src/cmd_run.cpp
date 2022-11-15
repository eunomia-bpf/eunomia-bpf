#include "ecli/cmd_entry.h"
#include <signal.h>
#include <clipp.h>

#include <iostream>

#include "ecli/eunomia_runner.h"
#include "ecli/url_resolver.h"

static void
run_mode_operation(const std::string &path,
                   const std::vector<std::string> &run_with_extra_args,
                   bool export_to_json, bool no_cache)
{
    export_format_type type;
    if (export_to_json) {
        type = export_format_type::EXPORT_JSON;
    }
    else {
        type = export_format_type::EXPORT_PLANT_TEXT;
    }
    auto base =
        program_config_data{ path,
                             !no_cache,
                             {},
                             program_config_data::program_type::UNDEFINE,
                             run_with_extra_args,
                             type };
    if (!resolve_url_path(base)) {
        std::cerr << "cannot resolve url data" << std::endl;
        return;
    }
    eunomia_runner r(base);
    r.thread = std::thread(&eunomia_runner::start_tracker, &r);
    printf("press 'Ctrl C' key to exit...");
    static volatile bool is_exiting = false;
    signal(SIGINT, [](int x) {
        printf("Ctrl C exit...");
        is_exiting = true;
        signal(SIGINT, SIG_DFL);
    });
    while (!is_exiting) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!r.is_running()) {
            is_exiting = true;
        }
    }
}

int
cmd_run_main(int argc, char *argv[])
{
    std::string ebpf_program_name = default_json_data_file_name;
    std::vector<std::string> run_with_extra_args;
    bool export_as_json = false, no_cache = false;

    auto run_url_value =
        clipp::value("url", ebpf_program_name)
        % "The url to get the ebpf program, can be file path or url.\n"
          "Or being \"--\" for receiving a json program from pipe.";
    auto run_opt_cmd_args = clipp::opt_values("extra args", run_with_extra_args)
                            % "Some extra args provided to the ebpf program";
    auto export_json_opt = clipp::option("-j", "--json")
                               .set(export_as_json)
                               .doc("export the result as json");
    auto no_cache_opt = clipp::option("-n", "--no-cache")
                            .set(no_cache)
                            .doc("export the result as json");

    auto run_cmd =
        (no_cache_opt, export_json_opt, run_url_value, run_opt_cmd_args)
        % "run a ebpf program";
    if (!clipp::parse(argc, argv, run_cmd)) {
        std::cout << clipp::make_man_page(run_cmd, argv[0]);
        return 1;
    }
    run_mode_operation(ebpf_program_name, run_with_extra_args, export_as_json,
                       no_cache);
    return 0;
}