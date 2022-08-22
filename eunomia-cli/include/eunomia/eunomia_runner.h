/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef PROCESS_CMD_H
#define PROCESS_CMD_H

#include <string>

#include "model/tracker.h"

struct eunomia_env
{
  std::vector<std::string> args;
  std::vector<char> buffer;
};

struct eunomia_event
{
  /// pid for the event
  int pid;
  /// the message for the event
  /// note this may be multi-line
  std::string messages;
};

class eunomia_runner : public tracker_with_exporter<eunomia_env, eunomia_event>
{
 public:
  /// create a tracker with deafult config
  static std::unique_ptr<eunomia_runner> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args)
  {
    return nullptr;
  }

  /// start process tracker
  void start_tracker();

  struct plain_text_event_printer : public event_handler<eunomia_event>
  {
    void handle(tracker_event<eunomia_event> &e);
  };
};

#endif