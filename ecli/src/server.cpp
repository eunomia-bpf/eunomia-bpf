#include "ecli/server.h"
#include "ecli/url_resolver.h"
#include <spdlog/spdlog.h>

#include <json.hpp>

#include "ecli/config.h"

#define get_from_json_at(name)                       \
    try {                                            \
        j.at(#name).get_to(data.name);               \
    } catch (...) {                                  \
        spdlog::warn("{} use default value", #name); \
    }

static void
from_json(const nlohmann::json &j, program_config_data &data)
{
    get_from_json_at(url);
    get_from_json_at(args);
}

eunomia_server::eunomia_server(ecli_config_data &config, int p)
  : core(config)
  , port(p)
{
}

void
eunomia_server::serve()
{
    server.Post(
        "/start", [=](const httplib::Request &req, httplib::Response &res) {
            spdlog::info("accept http start request");
            const std::lock_guard<std::mutex> lock(seq_mutex);
            std::string req_str;
            program_config_data data;
            try {
                /// try to start tracker directly
                auto id = core.start_tracker(req.body);
                if (!id) {
                    req_str = nlohmann::json{ "status", "error" }.dump();
                }
                else {
                    req_str = nlohmann::json{ "status", "ok", "id", id }.dump();
                }
            } catch (...) {
                spdlog::error("json parse error for tracker_config_data! {}",
                              req.body);
                res.status = 404;
                return;
            }
            res.status = 200;
            res.set_content(req_str, "text/plain");
        });

    server.Post(
        "/stop", [=](const httplib::Request &req, httplib::Response &res) {
            spdlog::info("accept http request to stop tracker");
            const std::lock_guard<std::mutex> lock(seq_mutex);
            std::string req_str;
            try {
                nlohmann::json j = nlohmann::json::parse(req.body);
                auto id = j.at("id").get<std::size_t>();
                core.stop_tracker(id);
                req_str = nlohmann::json{ "status", "ok" }.dump();
            } catch (...) {
                spdlog::error("json parse error for stop tracker {}", req.body);
                res.status = 404;
                return;
            }
            res.status = 200;
            res.set_content(req_str, "text/plain");
        });

    server.Get("/list", [=](const httplib::Request &req,
                            httplib::Response &res) {
        spdlog::info("accept http request for list");
        const std::lock_guard<std::mutex> lock(seq_mutex);
        std::string req_str;
        try {
            auto list = core.list_all_trackers();
            req_str = nlohmann::json{ "status", "ok", "list", list }.dump();
        } catch (...) {
            spdlog::error("json parse error for list trackers {}", req.body);
            res.status = 404;
            return;
        }
        res.status = 200;
        res.set_content(req_str, "text/plain");
    });
    core.start_eunomia();
    spdlog::info("eunomia server start at port {}", port);
    server.listen("localhost", port);
}

using json = nlohmann::json;

server_manager::server_manager(ecli_config_data &config)
  : core_config(config)
{
}

std::unique_ptr<eunomia_runner>
server_manager::create_default_tracker(program_config_data &base)
{
    return eunomia_runner::create_tracker_with_args(base);
}

std::vector<std::tuple<int, std::string>>
server_manager::list_all_trackers(void)
{
    return core_tracker_manager.get_tracker_list();
}

void
server_manager::stop_tracker(std::size_t tracker_id)
{
    core_tracker_manager.remove_tracker(tracker_id);
}

std::size_t
server_manager::start_tracker(program_config_data &config)
{
    spdlog::debug("tracker is starting from {}...", config.url);
    auto tracker = create_default_tracker(config);
    if (!tracker) {
        return 0;
    }
    return core_tracker_manager.start_tracker(std::move(tracker), config.url);
}

std::size_t
server_manager::start_tracker(const std::string &json_data)
{
    spdlog::debug("tracker is starting...");
    auto config_data =
        program_config_data{ "",
                             std::vector<char>(json_data.begin(),
                                               json_data.end()),
                             program_config_data::program_type::JSON_EUNOMIA,
                             {} };
    return start_tracker(config_data);
}

std::size_t
server_manager::start_trackers(void)
{
    std::size_t tracker_count = 0;
    for (auto &t : core_config.enabled_trackers) {
        spdlog::info("start ebpf tracker...");
        tracker_count += static_cast<std::size_t>(start_tracker(t) > 0 ? 1 : 0);
    }
    return tracker_count;
}

void
server_manager::check_auto_exit(std::size_t checker_count)
{
    if (core_config.exit_after > 0) {
        spdlog::info("set exit time...");
        std::this_thread::sleep_for(
            std::chrono::seconds(core_config.exit_after));
        // do nothing in server mode
    }
}

int
server_manager::start_eunomia(void)
{
    spdlog::info("start eunomia...");
    try {
        std::size_t checker_count = start_trackers();
        check_auto_exit(checker_count);
    } catch (const std::exception &e) {
        spdlog::error("eunomia start failed: {}", e.what());
        return 1;
    }
    spdlog::debug("eunomia exit. see you next time!");
    return 0;
}
