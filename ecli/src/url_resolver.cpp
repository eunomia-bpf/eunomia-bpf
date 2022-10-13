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
try_download_with_curl(const std::string &url, program_config_data &config_data)
{
    std::string resource_name = url.substr(url.find_last_of("/") + 1);
    auto path = default_download_path + resource_name;
    auto cmd =
        std::string("mkdir -p /tmp/ebpm/ && curl --no-progress-meter -o ")
        + path + " " + url;
    spdlog::info("{}", cmd);
    int res = std::system(cmd.c_str());
    if (res >= 0 && fs::exists(path)) {
        config_data.program_data_buffer = get_file_contents(path);
        return true;
    }
    spdlog::warn("failed to curl {}", url);
    return false;
}

static bool
resolve_package_type(program_config_data &config_data)
{
    if (str_ends_with(config_data.url, ".json")) {
        config_data.prog_type = program_config_data::program_type::JSON_EUNOMIA;
    }
    else if (str_ends_with(config_data.url, ".wasm")) {
        config_data.prog_type = program_config_data::program_type::WASM_MODULE;
    }
    else {
        spdlog::error("unknown file type: {}", config_data.url);
        return false;
    }
    return true;
}

static std::string
get_repo_base_url_from_env(void)
{
    auto base = std::getenv(repo_base_env_var_name);
    if (base == nullptr) {
        return default_repo_base_url;
    }
    return base;
}

static bool
resolve_regular_url_path(program_config_data &config_data) {
    // regular file
    if (fs::is_regular_file(config_data.url)) {
        spdlog::debug("data path is a file: {}", config_data.url);
        config_data.program_data_buffer = get_file_contents(config_data.url);
        return resolve_package_type(config_data);
    }
    // http links
    if (config_data.url.length() > 4
        && std::strncmp(config_data.url.c_str(), "http", 4) == 0) {
        if (try_download_with_curl(config_data.url, config_data)) {
            return resolve_package_type(config_data);
        }
    }
}

static bool
try_dwnload_from_repo(const std::string &name, program_config_data &config_data)
{
    auto url = get_repo_base_url_from_env() + name + "/app.wasm";
    std::cout << "trying to download from " << url << std::endl;
    config_data.url = url;
    return resolve_regular_url_path(config_data);
}

bool
resolve_url_path(program_config_data &config_data)
{
    if (resolve_regular_url_path(config_data)) {
        return true;
    }
    // from repository
    if (try_dwnload_from_repo(config_data.url, config_data)) {
        return true;
    }
    spdlog::error("data path not exits: {}", config_data.url);
    return false;
}
