/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia_runner.h"

#include <spdlog/spdlog.h>

#include <json.hpp>

#include "eunomia-bpf.h"

using json = nlohmann::json;

void eunomia_runner::start_tracker()
{
}

void eunomia_runner::plain_text_event_printer::handle(tracker_event<eunomia_event> &e)
{
}
