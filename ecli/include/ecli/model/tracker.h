/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef TRAKER_H
#define TRAKER_H

#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

/// the base type of a tracker

/// Base class used for tracker manager to manage tracker thread
class tracker_base
{
  /// base thread
  std::thread thread;
  /// for sync use
  std::mutex mutex;
  friend class tracker_manager;

 public:
  /// is the tracker exiting
  volatile bool exiting;
  /// constructor
  virtual ~tracker_base()
  {
  }
  /// start the tracker thread
  virtual void start_tracker(void) = 0;
  /// stop the tracker thread
  void stop_tracker(void)
  {
    exiting = true;
    if (thread.joinable())
    {
      thread.join();
    }
  }
};

#endif
