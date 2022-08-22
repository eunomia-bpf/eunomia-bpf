/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia/eunomia_core.h"

#include <signal.h>
#include <unistd.h>

#include <json.hpp>
#include <optional>

#include "eunomia/eunomia_runner.h"
#include "eunomia/tracker_manager.h"
#include "eunomia/url_resolver.h"
#include "spdlog/spdlog.h"

using json = nlohmann::json;

eunomia_core::eunomia_core(eunomia_config_data& config) : core_config(config)
{
}

template<typename TRACKER>
typename TRACKER::tracker_event_handler eunomia_core::create_tracker_event_handler(const handler_config_data& config)
{
  // spdlog::info("create event handler for {}", config.name);
  if (config.name == "plain_text")
  {
    return std::make_shared<typename TRACKER::plain_text_event_printer>();
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

template<typename TRACKER>
typename TRACKER::tracker_event_handler eunomia_core::create_tracker_event_handlers(
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
template<typename TRACKER>
std::unique_ptr<TRACKER> eunomia_core::create_tracker_with_handler(
    const tracker_config_data& base,
    typename TRACKER::tracker_event_handler additional_handler)
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
  auto json_data = resolve_json_data(base);
  if (!json_data)
  {
    return nullptr;
  }
  return TRACKER::create_tracker_with_args(handler, *json_data, base.args);
}

template<typename TRACKER>
std::unique_ptr<TRACKER> eunomia_core::create_default_tracker(const tracker_config_data& base)
{
  return create_tracker_with_handler<TRACKER>(base, nullptr);
}

std::vector<std::tuple<int, std::string>> eunomia_core::list_all_trackers(void)
{
  return core_tracker_manager.get_tracker_list();
}

void eunomia_core::stop_tracker(std::size_t tracker_id)
{
  core_tracker_manager.remove_tracker(tracker_id);
}

int eunomia_core::start_tracker(const tracker_config_data& config)
{
  spdlog::info("{} tracker is starting...", config.url);
  return core_tracker_manager.start_tracker(create_default_tracker<eunomia_runner>(config), config.url);
}

int eunomia_core::start_tracker(const std::string& json_data)
{
  spdlog::info("network tracker is starting...");
  auto tracker = create_default_tracker<eunomia_runner>(tracker_config_data{ "", json_data, {}, {} });
  spdlog::info("tracker name: {}", tracker->get_name());
  return core_tracker_manager.start_tracker(std::move(tracker), tracker->get_name());
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

int eunomia_core::start_eunomia(void)
{
  spdlog::info("start eunomia...");
  try
  {
    start_trackers();
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
