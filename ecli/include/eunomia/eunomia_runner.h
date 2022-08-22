/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef PROCESS_CMD_H
#define PROCESS_CMD_H

#include <memory>
#include <string>

#include "eunomia-bpf.h"
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
  static std::unique_ptr<eunomia_runner>
  create_tracker_with_args(tracker_event_handler handler, const std::string &json_data, const std::vector<std::string> &args)
  {
    return std::make_unique<eunomia_runner>(json_data, args, handler);
  }
  eunomia_runner(const std::string &json_data, const std::vector<std::string> &args, tracker_event_handler handler)
      : program{ json_data },
        tracker_with_exporter{ export_data{
            eunomia_env{},
            program.get_program_name(),
            handler
        } }
  {
  }

  /// start process tracker
  void start_tracker();
  const std::string get_name(void) const {
    return program.get_program_name();
  }

  struct plain_text_event_printer : public event_handler<eunomia_event>
  {
    void handle(tracker_event<eunomia_event> &e);
  };

 private:
  eunomia_ebpf_program program;
};

#endif