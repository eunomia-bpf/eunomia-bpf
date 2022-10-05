#include "ecli/url_resolver.h"

#include <filesystem>

#include "httplib.h"
#include "spdlog/spdlog.h"

namespace fs = std::filesystem;

constexpr auto default_download_path = "/tmp/ebpm/";

static std::string get_file_contents(const std::string& path)
{
  std::ifstream json_file(path);
  return std::string((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
}

static bool try_download_with_wget(const std::string& url, program_config_data& config_data)
{
  std::string resource_name = url.substr(url.find_last_of("/") + 1);
  auto path = default_download_path + resource_name;
  auto cmd = std::string("mkdir -p /tmp/ebpm/ && wget --no-verbose --output-document=") + path + " " + url;
  spdlog::info("{}", cmd);
  int res = std::system(cmd.c_str());
  if (res >= 0 && fs::exists(path))
  {
    config_data.json_data = get_file_contents(path);
    return true;
  }
  spdlog::error("failed to wget {}", url);
  return false;
}

bool resolve_url_path(program_config_data& config_data)
{
  if (config_data.url == "")
  {
    spdlog::debug("url is empty, use json_data directly");
    // accept a web requests or others, try to use json_data directly.
    return true;
  }
  if (fs::is_regular_file(config_data.url))
  {
    spdlog::debug("data path is a file: {}", config_data.url);
    config_data.json_data = get_file_contents(config_data.url);
    return true;
  }
  if (config_data.url.length() > 4 && std::strncmp(config_data.url.c_str(), "http", 4) == 0)
  {
    std::size_t found_host = config_data.url.find_first_of(":");
    std::string host = config_data.url.substr(0, found_host);
    std::size_t found_resourse = config_data.url.find_first_of("/");
    std::string port = config_data.url.substr(found_host + 1, found_resourse - found_host - 1);
    std::string resource = config_data.url.substr(found_resourse);

    httplib::Client client(config_data.url);
    auto res = client.Get("");
    if (!res)
    {
      spdlog::debug("Connection failed.");
      return try_download_with_wget(config_data.url, config_data);
    }
    if (res->status == 404)
    {
      spdlog::debug("Not found.");
      return try_download_with_wget(config_data.url, config_data);
    }
    spdlog::info("Get data complete: {}", res->status);
    config_data.json_data = res->body;
    return true;
  }
  spdlog::error("data path not exits: {}", config_data.url);
  return false;
}
