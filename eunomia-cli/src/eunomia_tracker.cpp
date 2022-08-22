/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include <spdlog/spdlog.h>

#include <json.hpp>

#include "eunomia/process.h"

using json = nlohmann::json;

void eunomia_tracker::start_tracker()
{
}

void eunomia_tracker::plain_text_event_printer::handle(tracker_event<process_event> &e)
{
}
