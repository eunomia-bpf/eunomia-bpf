/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef IPC_CMD_H
#define IPC_CMD_H

#include "libbpf_print.h"
#include "model/tracker.h"
#include "prometheus_server.h"

extern "C" {
#include <ipc/ipc_tracker.h>
}

/// ebpf LSM ipc tracker
struct ipc_tracker : public tracker_with_config<ipc_env, ipc_event> {

  ipc_tracker(config_data config);

  // create a tracker with deafult config
  static std::unique_ptr<ipc_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<ipc_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args)
  {
    return create_tracker_with_default_env(handler);
  }

  void start_tracker();

  // convert event to json
  struct json_event_handler : public event_handler<ipc_event>
  {
    std::string to_json(const struct ipc_event &e);
  };

  // used for json exporter, inherits from json_event_handler
  struct json_event_printer : public json_event_handler
  {
    void handle(tracker_event<ipc_event> &e);
  };

  struct plain_text_event_printer : public event_handler<ipc_event>
  {
    void handle(tracker_event<ipc_event> &e);
  };

  struct csv_event_printer : public event_handler<ipc_event>
  {
    void handle(tracker_event<ipc_event> &e);
  };
};

#endif
