#ifndef URL_RESOLVER_H
#define URL_RESOLVER_H

#include<string>
#include<optional>
#include "config.h"

std::optional<std::string> resolve_json_data(const tracker_config_data& config_data);

#endif
