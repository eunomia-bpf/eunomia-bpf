/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia/prometheus_server.h"
#include "eunomia/tracker_integrations.h"

//#include <gtest/gtest.h>

#include "eunomia/tracker_manager.h"

using namespace std::chrono_literals;

int main(int argc, char **argv)
{
  {
    tracker_manager manager;
    std::cout << "start ebpf...\n";

    auto test_event_printer =
        std::make_shared<tcpconnlat_tracker::plain_text_event_printer>(tcpconnlat_tracker::plain_text_event_printer{});

    auto tracker_ptr = tcpconnlat_tracker::create_tracker_with_default_env(std::move(test_event_printer));
    manager.start_tracker(std::move(tracker_ptr), "");
    std::this_thread::sleep_for(10s);
  }
  return 0;
}
