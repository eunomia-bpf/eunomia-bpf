/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef TRACKER_MANAGER_H
#define TRACKER_MANAGER_H

#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>
#include <map>
#include "model/tracker.h"

/// tracker manager for owning and managing tracker instances

/// provide interface for list, start and exit trackers
/// RAII style
class tracker_manager
{
 private:
  struct tracker_base_data {
    std::string name;
    std::unique_ptr<tracker_base> tracker;
  };
  std::size_t id_count = 1;
  std::map<std::size_t,  tracker_base_data> trackers;

 public:
  ~tracker_manager() {
  }
  // remove a tracker with id
  int remove_tracker(std::size_t id)
  {
    if (trackers.erase(id) == 0) {
      return -1;
    }
    return 0;
  }
  // get tracker lists
  // return a list of tracker id and name
  std::vector<std::tuple<int, std::string>> get_tracker_list()
  {
    std::vector<std::tuple<int, std::string>> list;
    for (auto &[id, data] : trackers) {
      list.push_back({id, data.name});
    }
    return list;
  }
  // start a tracker and return id
  std::size_t start_tracker(std::unique_ptr<tracker_base> tracker_ptr, const std::string &name)
  {
    if (!tracker_ptr)
    {
      std::cout << "tracker_ptr is null in start_tracker\n";
      return 0;
    }
    std::size_t id = id_count++;
    tracker_ptr->thread = std::thread(&tracker_base::start_tracker, tracker_ptr.get());
    trackers.emplace(id, tracker_base_data{name, std::move(tracker_ptr)});
    return id;
  }
  // stop all tracker
  void remove_all_trackers()
  {
    trackers.clear();
  }
};

#endif
