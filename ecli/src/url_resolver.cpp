#include "ecli/url_resolver.h"

#include <filesystem>

#include "httplib.h"
#include "spdlog/spdlog.h"

namespace fs = std::filesystem;

constexpr auto default_download_path = "/tmp/ebpm/";

static std::optional<std::string> try_download_with_wget(const std::string& url)
{
  std::string resource_name = url.substr(url.find_last_of("/") + 1);
  auto path = default_download_path + resource_name;
  auto cmd = std::string("mkdir -p /tmp/ebpm/ && wget --no-verbose --output-document=") + path + " " + url;
  spdlog::info("{}", cmd);
  int res = std::system(cmd.c_str());
  if (res >= 0 && fs::exists(path))
  {
    std::ifstream json_file(path);
    spdlog::info("wget download success.");
    return std::string((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
  }
  spdlog::error("failed to wget {}", url);
  return std::nullopt;
}

std::optional<std::string> resolve_json_data(const tracker_config_data& config_data)
{
  if (config_data.url == "")
  {
    spdlog::info("url is empty, use json_data directly");
    // accept a web requests or others, try to use json_data directly.
    return config_data.json_data;
  }
  if (fs::is_regular_file(config_data.url))
  {
    std::ifstream json_file(config_data.url);
    spdlog::info("reading json data from regular file {}", config_data.url);
    return std::string((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
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
      spdlog::info("Connection failed.");
      return try_download_with_wget(config_data.url);
    }
    if (res->status == 404)
    {
      spdlog::info("Not found.");
      return try_download_with_wget(config_data.url);
    }
    spdlog::info("Get json data complete: {}", res->status);
    return res->body;
  }
  spdlog::error("json data path not exits: {}", config_data.url);
  return std::nullopt;
}
