/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef TRACKER_CONFIG_H
#define TRACKER_CONFIG_H

#include <mutex>
#include <thread>
#include "event_handler.h"

/// the config env for a tracker
template<typename ENV>
concept env_concept = requires {
    /// is the tracker exiting?

    /// If this is true, the tracker should exit.
    typename ENV::exiting;
};

/// config data for tracker

/// pass this to create a tracker
template <typename ENV, typename EVENT>
struct tracker_config
{
    /// tracker env in C code
    ENV env;
    /// tracker name
    std::string name;
    /// event handler interface
    std::shared_ptr<event_handler<EVENT>> handler = nullptr;
};

#endif
