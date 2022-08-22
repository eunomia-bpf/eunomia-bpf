#include "url_resolver.h"

#include <filesystem>

#include "httplib.h"
#include "spdlog/spdlog.h"

namespace fs = std::filesystem;

std::optional<std::string> resolve_json_data(const tracker_config_data& config_data)
{
  if (config_data.url == "")
  {
    // accept a web requests or others, try to use json_data directly.
    return config_data.json_data;
  }
  if (fs::is_regular_file(config_data.url))
  {
    if (!fs::exists(config_data.url))
    {
      return std::nullopt;
    }
    std::ifstream json_file(config_data.url);
    return std::string((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
  }
  if (config_data.url.length() > 4 && std::strncmp(config_data.url.c_str(), "http", 4) == 0)
  {
    httplib::Client client(config_data.url);

    // prints: 0 / 000 bytes => 50% complete
    auto res = client.Get("/", [](uint64_t len, uint64_t total) {
      printf("%lld / %lld bytes => %d%% complete\r", len, total, (int)(len * 100 / total));
      return true;
    });
    spdlog::info("Get json data complete.");
    // FIXME: check OK
    return res->body;
  }
}