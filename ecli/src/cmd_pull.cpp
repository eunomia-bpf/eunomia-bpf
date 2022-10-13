#include "ecli/cmd_entry.h"
#include <signal.h>
#include <clipp.h>
#include <spdlog/spdlog.h>

#include <iostream>
#include <fstream>

#include "ecli/eunomia_runner.h"
#include "ecli/url_resolver.h"

static void
save_to_file(const std::string &path, const program_config_data &base)
{
    // save as basic name
    std::ofstream out(path);
    // write vector to buffer
    out.write(base.program_data_buffer.data(), base.program_data_buffer.size());
    out.close();
}

static void
pull_mode_operation(const std::string &path, bool no_cache)
{
    auto base = program_config_data{
        path, !no_cache, {}, program_config_data::program_type::UNDEFINE, {}, {}
    };
    if (!resolve_url_path(base)) {
        std::cerr << "cannot resolve url data" << std::endl;
        return;
    }
    // same as run_mode_operation, but without eunomia_runner
    // FIXME: save to local
    std::size_t last_split = path.find_last_of("/");
    if (last_split == std::string::npos) {
        // a simple name
        save_to_file(path, base);
    }
    // a http link, save the last part
    save_to_file(path.substr(last_split + 1), base);
}

int
cmd_pull_main(int argc, char *argv[])
{
    std::string ebpf_program_name = default_json_data_file_name;
    bool no_cache = false;

    auto run_url_value =
        clipp::value("url", ebpf_program_name)
        % "The url to get the ebpf program, can be file path or url";
    auto no_cache_opt = clipp::option("-n", "--no-cache")
                            .set(no_cache)
                            .doc("export the result as json");
    auto pull_cmd = (run_url_value, no_cache_opt)
                    % "pull a ebpf program from remote to local";
    if (!clipp::parse(argc, argv, pull_cmd)) {
        std::cout << clipp::make_man_page(pull_cmd, argv[0]);
        return 1;
    }
    pull_mode_operation(ebpf_program_name, no_cache);
    return 0;
}
