#include "ecli/url_resolver.h"

#include <filesystem>

#include "httplib.h"
#include "spdlog/spdlog.h"
#include "eunomia/utils.hpp"

namespace fs = std::filesystem;

constexpr auto default_download_path = "/tmp/ebpm/";

static std::vector<char>
get_file_contents(const std::string &path)
{
    std::ifstream json_file(path);
    return std::vector<char>((std::istreambuf_iterator<char>(json_file)),
                             std::istreambuf_iterator<char>());
}

static bool
try_download_with_wget(const std::string &url, program_config_data &config_data)
{
    std::string resource_name = url.substr(url.find_last_of("/") + 1);
    auto path = default_download_path + resource_name;
    auto cmd =
        std::string(
            "mkdir -p /tmp/ebpm/ && wget --no-verbose --output-document=")
        + path + " " + url;
    spdlog::info("{}", cmd);
    int res = std::system(cmd.c_str());
    if (res >= 0 && fs::exists(path)) {
        config_data.program_data_buffer = get_file_contents(path);
        return true;
    }
    spdlog::error("failed to wget {}", url);
    return false;
}

bool
resolve_url_path(program_config_data &config_data)
{
    bool res;
    if (config_data.url == "") {
        spdlog::debug("url is empty, use json_data directly");
        res = false;
    }
    if (fs::is_regular_file(config_data.url)) {
        spdlog::debug("data path is a file: {}", config_data.url);
        config_data.program_data_buffer = get_file_contents(config_data.url);
        res = true;
    }
    if (config_data.url.length() > 4
        && std::strncmp(config_data.url.c_str(), "http", 4) == 0) {
        res = try_download_with_wget(config_data.url, config_data);
    }
    if (res) {
        if (str_ends_with(config_data.url, ".json")) {
            config_data.prog_type =
                program_config_data::program_type::JSON_EUNOMIA;
        }
        else if (str_ends_with(config_data.url, ".wasm")) {
            config_data.prog_type =
                program_config_data::program_type::WASM_MODULE;
        }
        else {
            spdlog::error("unknown file type: {}", config_data.url);
            res = false;
        }
        return res;
    }
    spdlog::error("data path not exits: {}", config_data.url);
    return false;
}
