#include "ecli/url_resolver.h"

#include <filesystem>
#include <regex>
#include "httplib.h"
#include "spdlog/spdlog.h"
#include "eunomia/utils.hpp"

namespace fs = std::filesystem;

static std::vector<char>
get_file_contents(const std::string &path)
{
    std::ifstream json_file(path);
    return std::vector<char>((std::istreambuf_iterator<char>(json_file)),
                             std::istreambuf_iterator<char>());
}

static std::string
get_remote_repo_base_url_from_env(void)
{
    auto base = std::getenv(remote_repo_base_env_var_name);
    if (base == nullptr) {
        return default_repo_base_url;
    }
    return base;
}

std::string
get_local_home_path_from_env(void)
{
    auto base = std::getenv(local_home_env_var_name);
    if (base == nullptr) {
        return default_local_home_path;
    }
    return base;
}

static fs::path
get_url_local_path(const std::string &url)
{
    // url: https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/package.json
    std::size_t last_split = url.find_last_of("/");
    std::size_t last_next_split = url.find_last_of("/", last_split - 1);
    if (last_split == std::string::npos
        || last_next_split == std::string::npos) {
        throw std::runtime_error("invalid url in get_url_local_path");
    }
    // dir_name: sigsnoop
    auto dir_name =
        url.substr(last_next_split + 1, last_split - last_next_split);
    // resource_name: package.json
    std::string resource_name = url.substr(last_split + 1);
    // path: ~/.ebpm/sigsnoop/package.json
    auto path =
        std::filesystem::path(fs::absolute(get_local_home_path_from_env()))
        / dir_name / resource_name;
    return path;
}

static bool
try_download_with_curl(const std::string &url, program_config_data &config_data)
{
    auto path = get_url_local_path(url);
    // use cache instead
    if (config_data.use_cache && fs::exists(path)) {
        std::cout << "use cache: " << path << std::endl;
        config_data.program_data_buffer = get_file_contents(path);
        return true;
    }
    // save the data to local repository
    auto cmd = std::string("mkdir -p ") + path.parent_path().string()
               + " && curl --fail --no-progress-meter -o " + path.string() + " "
               + url;
    std::cout << "download with curl: " << url << std::endl;
    int res = std::system(cmd.c_str());
    if (res == 0 && fs::exists(path)) {
        config_data.program_data_buffer = get_file_contents(path);
        return true;
    }
    spdlog::debug("failed to curl {}", url);
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
        return false;
    }
    return true;
}

// accept url like:
// https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/package.json
// https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/app.wasm
// ./sigsnoop/package.json
static bool
resolve_regular_url_path(program_config_data &config_data)
{
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
    return false;
}

static bool
get_content_in_new_config(program_config_data &config_data,
                          const std::string &url)
{
    program_config_data new_config_data = config_data;
    new_config_data.url = url;
    int res = resolve_regular_url_path(new_config_data);
    if (res) {
        config_data = new_config_data;
        return true;
    }
    return false;
}

static bool
try_get_content_from_name(const std::string &name,
                          program_config_data &config_data)
{
    // name should be in the format of program_name:tag
    std::regex name_regex("([a-zA-Z0-9_]+):?([a-zA-Z0-9_]*)");
    std::smatch match;
    if (!std::regex_match(name, match, name_regex)) {
        return false;
    }
    auto program_name = match[1].str();
    // TODO: support tag
    auto tag = match[2].str();
    if (tag == "latest") {
        config_data.use_cache = false;
    }
    // try get wasm module
    auto url = get_remote_repo_base_url_from_env() + program_name + "/app.wasm";
    if (get_content_in_new_config(config_data, url)) {
        return true;
    }
    // try get json file
    url = get_remote_repo_base_url_from_env() + program_name + "/package.json";
    if (get_content_in_new_config(config_data, url)) {
        return true;
    }
    return false;
}

bool
resolve_url_path(program_config_data &config_data)
{
    if (resolve_regular_url_path(config_data)) {
        return true;
    }
    // from repository
    if (try_get_content_from_name(config_data.url, config_data)) {
        return true;
    }

    // from pip stdin
    if (config_data.url == "--") {
        namespace ct = std::chrono;
        using namespace std;
        if(isatty(fileno(stdin))) {
            std::cout << "please input a file by pipe.\n";
            return false;
        } else {
            std::cout << "-- mode\n";
        }
        ct::system_clock::duration d = ct::system_clock::now().time_since_epoch();
        ct::seconds sec = ct::duration_cast<ct::seconds>(d);
        std::string tmpname = "tmp" + std::to_string(sec.count()) + ".json";

        std::ofstream out(tmpname);
        if(!out.is_open()) {
            std::cout << "create file failure! please check the permission.\n";
            return false;
        }

        std::streambuf *stdcout = std::cout.rdbuf();
        std::cout.rdbuf(out.rdbuf());
        std::string buf;
        while(std::cin >> buf) {
            std::cout << buf << ' ';
        }
        out.close();
        std::cout.rdbuf(stdcout);
        config_data.url = tmpname;
        if (resolve_regular_url_path(config_data)) {
            return true;
        }
    }

    spdlog::error("unknown file type: {}", config_data.url);
    return false;
}
