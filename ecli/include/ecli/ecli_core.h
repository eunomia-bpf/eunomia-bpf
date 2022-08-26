/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef eunomia_runner_FACTORY_H
#define eunomia_runner_FACTORY_H

#include <optional>

#include "config.h"
#include "ecli/config.h"
#include "ecli/eunomia_runner.h"
#include "ecli/tracker_manager.h"

/// core for building tracker

/// construct tracker with handlers
/// and manage state
struct ecli_core
{
 private:
  /// eunomia config
  eunomia_config_data core_config;

  /// manager for all tracker
  tracker_manager core_tracker_manager;

  /// if the config is invalid, it will return a nullptr.
  eunomia_runner::tracker_event_handler create_tracker_event_handler(const handler_config_data& config);
  /// create all event handlers for a tracker
  eunomia_runner::tracker_event_handler create_tracker_event_handlers(
      const std::vector<handler_config_data>& handler_configs);

  std::unique_ptr<eunomia_runner> create_default_tracker(const tracker_config_data& base);

  /// create a default tracker with other handlers
  std::unique_ptr<eunomia_runner> create_tracker_with_handler(
      const tracker_config_data& base,
      eunomia_runner::tracker_event_handler);

  /// start all trackers
  std::size_t start_trackers(void);
  /// check and stop all trackers if needed
  void check_auto_exit(std::size_t checker_count);

 public:
  ecli_core(eunomia_config_data& config);
  /// start the core
  int start_eunomia(void);
  /// start a single tracker base on config
  std::size_t start_tracker(const tracker_config_data& config);
  std::size_t start_tracker(const std::string& json_data);
  /// list all trackers
  std::vector<std::tuple<int, std::string>> list_all_trackers(void);
  /// stop a tracker by id
  void stop_tracker(std::size_t tracker_id);
};

#endif
