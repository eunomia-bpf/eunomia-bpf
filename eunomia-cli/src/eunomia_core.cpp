/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia/eunomia_core.h"

#include <spdlog/spdlog.h>

#include <filesystem>

#include "eunomia/sec_analyzer.h"
#include "eunomia/tracker_integrations.h"
#include "eunomia/tracker_manager.h"

eunomia_core::eunomia_core(eunomia_config_data& config)
    : core_config(config),
      core_prometheus_server(config.prometheus_listening_address, core_container_manager)
{
  if (!std::filesystem::exists("/var/run/docker.pid"))
  {
    spdlog::warn("Failed to find container daemon. Disabling container tracking.");
    core_config.enable_container_manager = false;
  }
  core_config.load_config_options_to_trackers();
}

template<tracker_concept TRACKER>
TRACKER::tracker_event_handler eunomia_core::create_tracker_event_handler(const handler_config_data& config)
{
  // spdlog::info("create event handler for {}", config.name);
  if (config.name == "json_format")
  {
    return std::make_shared<typename TRACKER::json_event_printer>();
  }
  else if (config.name == "plain_text")
  {
    return std::make_shared<typename TRACKER::plain_text_event_printer>();
  }
  else if (config.name == "csv")
  {
    return std::make_shared<typename TRACKER::csv_event_printer>();
  }
  else if (config.name == "prometheus")
  {
    return std::make_shared<typename TRACKER::prometheus_event_handler>(
        typename TRACKER::prometheus_event_handler(core_prometheus_server));
  }
  else if (config.name == "container_info")
  {
    return std::make_shared<container_manager::container_info_handler<typename TRACKER::event>>(
        container_manager::container_info_handler<typename TRACKER::event>{ core_container_manager });
  }
  else if (config.name == "none")
  {
    return nullptr;
  }
  else
  {
    spdlog::error("unsupported event handler {}", config.name);
    return nullptr;
  }
}

template<tracker_concept TRACKER>
TRACKER::tracker_event_handler eunomia_core::create_tracker_event_handlers(
    const std::vector<handler_config_data>& handler_configs)
{
  typename TRACKER::tracker_event_handler handler = nullptr, base_handler = nullptr;
  for (auto& config : handler_configs)
  {
    auto new_handler = create_tracker_event_handler<TRACKER>(config);
    if (new_handler)
    {
      if (handler)
      {
        handler->add_handler(new_handler);
        handler = new_handler;
      }
      else
      {
        handler = new_handler;
        base_handler = new_handler;
      }
    }
  }
  return base_handler;
}

// create a default tracker with other handlers
template<tracker_concept TRACKER>
std::unique_ptr<TRACKER> eunomia_core::create_default_tracker_with_handler(
    const tracker_config_data& base,
    TRACKER::tracker_event_handler additional_handler)
{
  auto handler = create_tracker_event_handlers<TRACKER>(base.export_handlers);
  if (!handler && !additional_handler)
  {
    spdlog::error("no handler was created for tracker");
    return nullptr;
  }
  if (additional_handler)
  {
    additional_handler->add_handler(handler);
    handler = additional_handler;
  }
  if (base.args.empty())
  {
    return TRACKER::create_tracker_with_default_env(handler);
  }
  return TRACKER::create_tracker_with_args(handler, base.args);
}

template<tracker_concept TRACKER>
std::unique_ptr<TRACKER> eunomia_core::create_default_tracker(const tracker_config_data& base)
{
  return create_default_tracker_with_handler<TRACKER>(base, nullptr);
}

template<tracker_concept TRACKER, typename SEC_ANALYZER_HANDLER>
std::unique_ptr<TRACKER> eunomia_core::create_default_tracker_with_sec_analyzer(const tracker_config_data& base)
{
  std::shared_ptr<SEC_ANALYZER_HANDLER> handler = nullptr;
  if (core_config.enable_sec_rule_detect)
  {
    handler = std::make_shared<SEC_ANALYZER_HANDLER>(core_sec_analyzer);
  }
  return create_default_tracker_with_handler<TRACKER>(base, handler);
}

std::unique_ptr<process_tracker> eunomia_core::create_process_tracker_with_container_tracking(
    const tracker_config_data& base)
{
  std::shared_ptr<container_manager::container_tracking_handler> handler = nullptr;
  if (core_config.enable_container_manager)
  {
    handler = std::make_shared<container_manager::container_tracking_handler>(
        container_manager::container_tracking_handler{ core_container_manager });
  }
  return create_default_tracker_with_handler<process_tracker>(base, handler);
}

std::vector<std::tuple<int, std::string>> eunomia_core::list_all_trackers(void)
{
  return core_tracker_manager.get_tracker_list();
}

void eunomia_core::stop_tracker(std::size_t tracker_id)
{
  core_tracker_manager.remove_tracker(tracker_id);
}

std::optional<std::size_t> eunomia_core::start_tracker(const tracker_config_data& config)
{
  spdlog::info("{} tracker is starting...", config.name);
  if (config.name == "files")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<files_tracker>(config), config.name);
  }
  else if (config.name == "process")
  {
    return core_tracker_manager.start_tracker(create_process_tracker_with_container_tracking(config), config.name);
  }
  else if (config.name == "syscall")
  {
    return core_tracker_manager.start_tracker(
        create_default_tracker_with_sec_analyzer<syscall_tracker, syscall_rule_checker>(config), config.name);
  }
  else if (config.name == "tcpconnect")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<tcp_tracker>(config), config.name);
  }
  else if (config.name == "capable")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<capable_tracker>(config), config.name);
  }
  else if (config.name == "memleak")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<memleak_tracker>(config), config.name);
  }
  else if (config.name == "tcpconnlat")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<tcpconnlat_tracker>(config), config.name);
  }
  else if (config.name == "mountsnoop")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<mountsnoop_tracker>(config), config.name);
  }
  else if (config.name == "sigsnoop")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<sigsnoop_tracker>(config), config.name);
  }
  else if (config.name == "bindsnoop")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<bindsnoop_tracker>(config), config.name);
  }
  else if (config.name == "opensnoop")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<opensnoop_tracker>(config), config.name);
  }
  else if (config.name == "oomkill")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<oomkill_tracker>(config), config.name);
  }
  else if (config.name == "tcprtt")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<tcprtt_tracker>(config), config.name);
  }
  else if (config.name == "hotupdate")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<hotupdate_tracker>(config), config.name);
  }
  else if (config.name == "syscount")
  {
    // return core_tracker_manager.start_tracker(create_default_tracker<syscount_tracker>(config), config.name);
    return std::nullopt;
  }
  else if (config.name == "funclatency")
  {
    return core_tracker_manager.start_tracker(create_default_tracker<funclatency_tracker>(config), config.name);
  }
  else
  {
    spdlog::error("unknown tracker name: {}", config.name);
    return std::nullopt;
  }
}

void eunomia_core::start_trackers(void)
{
  for (auto& t : core_config.enabled_trackers)
  {
    spdlog::info("start ebpf tracker...");
    (void)start_tracker(t);
  }
}

void eunomia_core::check_auto_exit(void)
{
  if (core_config.exit_after > 0)
  {
    spdlog::info("set exit time...");
    std::this_thread::sleep_for(std::chrono::seconds(core_config.exit_after));
    // do nothing in server mode
  }
  else
  {
    if (core_config.run_selected != "server")
    {
      spdlog::info("press 'Ctrl C' key to exit...");
      static bool is_exiting = false;
      signal(SIGINT, [](int x) {
        spdlog::info("Ctrl C exit...");
        is_exiting = true;
        signal(SIGINT, SIG_DFL);
      });
      while (!is_exiting)
      {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }
  }
}

void eunomia_core::start_prometheus_server(void)
{
  if (core_config.enabled_export_types.count("prometheus"))
  {
    spdlog::info("start prometheus server...");
    core_prometheus_server.start_prometheus_server();
  }
}

void eunomia_core::start_sec_analyzer(void)
{
  if (core_config.enable_sec_rule_detect)
  {
    spdlog::info("start safe module...");
    if (core_config.enabled_export_types.count("prometheus"))
    {
      core_sec_analyzer = sec_analyzer_prometheus::create_sec_analyzer_with_default_rules(core_prometheus_server);
    }
    else
    {
      core_sec_analyzer = sec_analyzer::create_sec_analyzer_with_default_rules();
    }
  }
}

void eunomia_core::start_container_manager(void)
{
  if (core_config.enable_container_manager)
  {
    spdlog::info("start container manager...");
    core_container_manager.init();
    // found process tracker
    for (auto i : core_config.enabled_trackers)
    {
      if (i.name == "process")
      {
        return;
      }
    }
    // if not found, add it
    core_config.enabled_trackers.push_back(tracker_config_data{ "process", {} });
  }
}

int eunomia_core::start_eunomia(void)
{
  spdlog::info("start eunomia...");
  try
  {
    start_sec_analyzer();
    start_container_manager();
    start_trackers();
    start_prometheus_server();
    check_auto_exit();
  }
  catch (const std::exception& e)
  {
    spdlog::error("eunomia start failed: {}", e.what());
    return 1;
  }
  spdlog::debug("eunomia exit. see you next time!");
  return 0;
}
