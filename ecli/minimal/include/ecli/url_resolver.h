/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#ifndef ECLI_URL_RESOLVER_H
#define ECLI_URL_RESOLVER_H

#include <string>
#include <optional>
#include "config.h"

// Resolve the url path and load the data into the config
bool
resolve_url_path(program_config_data &config_data);

std::string
get_local_home_path_from_env(void);

#endif
