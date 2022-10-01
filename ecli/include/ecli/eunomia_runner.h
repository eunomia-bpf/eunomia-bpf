/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef EUNOMIA_RUNNER_H
#define EUNOMIA_RUNNER_H

#include <memory>
#include <string>

#include "eunomia/eunomia-bpf.hpp"
#include "config.h"
#include "model/tracker.h"

class eunomia_runner : public tracker_base
{
 public:
  /// create a tracker with deafult config
  static std::unique_ptr<eunomia_runner> create_tracker_with_args(const tracker_config_data& config)
  {
    return std::make_unique<eunomia_runner>(config);
  }

  eunomia_runner(const tracker_config_data& config);

  /// start process tracker
  void start_tracker();
  const std::string get_name(void) const
  {
    return program.get_program_name();
  }

 private:
  eunomia::eunomia_ebpf_program program;
  tracker_config_data current_config;
};

#endif