/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia/sec_analyzer.h"

#include <spdlog/spdlog.h>

const static sec_rule_describe default_rules[] = {
  sec_rule_describe{
      .level = sec_rule_level::event,
      .type = sec_rule_type::syscall,
      .name = "Insert-BPF",
      .message = "BPF program loaded",
      .signature = "bpf",
  },
  sec_rule_describe{
      .level = sec_rule_level::event,
      .type = sec_rule_type::syscall,
      .name = "Anti-Debugging",
      .message = "Process uses anti-debugging technique to block debugger",
      .signature = "ptrace",
  },
};

sec_analyzer_prometheus::sec_analyzer_prometheus(prometheus_server &server, const std::vector<sec_rule_describe> &in_rules)
    : sec_analyzer(in_rules),
      eunomia_sec_warn_counter(prometheus::BuildCounter()
                                   .Name("eunomia_seccurity_warn_count")
                                   .Help("Number of observed security warnings")
                                   .Register(*server.registry)),
      eunomia_sec_event_counter(prometheus::BuildCounter()
                                    .Name("eunomia_seccurity_event_count")
                                    .Help("Number of observed security event")
                                    .Register(*server.registry)),
      eunomia_sec_alert_counter(prometheus::BuildCounter()
                                    .Name("eunomia_seccurity_alert_count")
                                    .Help("Number of observed security alert")
                                    .Register(*server.registry))
{
}

std::string sec_rule_level_string(sec_rule_level level)
{
  switch (level)
  {
    case sec_rule_level::warnning: return "warnning";
    case sec_rule_level::event: return "event";
    case sec_rule_level::alert: return "alert";
    default: return "unknown";
  }
}

void sec_analyzer::print_event(const rule_message &msg)
{
  spdlog::info("{}", "Security Rule Detection:");
  spdlog::info("level: {}", sec_rule_level_string(msg.level));
  spdlog::info("name: {}", msg.name);
  spdlog::info("message: {}", msg.message);
  spdlog::info("pid: {}", msg.pid);
  spdlog::info("container_id: {}", msg.container_id);
  spdlog::info("container_name: {}", msg.container_name);
}

void sec_analyzer::report_event(const rule_message &msg)
{
  print_event(msg);
}

void sec_analyzer_prometheus::report_event(const rule_message &msg)
{
  print_event(msg);
  report_prometheus_event(msg);
}

void sec_analyzer_prometheus::report_prometheus_event(const struct rule_message &msg)
{
  switch (msg.level)
  {
    case sec_rule_level::event:
      eunomia_sec_event_counter
          .Add({ { "level", "event" },
                 { "name", msg.name },
                 { "message", msg.message },
                 { "pid", std::to_string(msg.pid) },
                 { "container_id", msg.container_id },
                 { "container_name", msg.container_name } })
          .Increment();
      break;
    case sec_rule_level::warnning:
      eunomia_sec_warn_counter
          .Add({ { "level", "warning" },
                 { "name", msg.name },
                 { "message", msg.message },
                 { "pid", std::to_string(msg.pid) },
                 { "container_id", msg.container_id },
                 { "container_name", msg.container_name } })
          .Increment();
      break;
    case sec_rule_level::alert:
      eunomia_sec_alert_counter
          .Add({ { "level", "alert" },
                 { "name", msg.name },
                 { "message", msg.message },
                 { "pid", std::to_string(msg.pid) },
                 { "container_id", msg.container_id },
                 { "container_name", msg.container_name } })
          .Increment();
      break;
    default: break;
  }
}

int syscall_rule_checker::check_rule(const tracker_event<syscall_event> &e, rule_message &msg)
{
  if (!analyzer)
  {
    return -1;
  }
  if (e.data.pid == getpid())
  {
    return -1;
  }
  for (std::size_t i = 0; i < analyzer->rules.size(); i++)
  {
    if (analyzer->rules[i].type == sec_rule_type::syscall &&
        analyzer->rules[i].signature == syscall_names_x86_64[e.data.syscall_id])
    {
      msg.level = analyzer->rules[i].level;
      msg.name = analyzer->rules[i].name;
      msg.message = analyzer->rules[i].message + ": " + e.data.comm;
      msg.pid = e.data.pid;
      // EVNETODO: fix get container id
      msg.container_id = "36fca8c5eec1";
      msg.container_name = "Ubuntu";
      return (int)i;
    }
  }
  return -1;
}

/*

examples:

[bpf_rule]
type = "syscall"
name = "Insert-BPF"
syscall = "bpf"
error_message = "BPF program loaded"

[debug]
type = "syscall"
name = "Anti-Debugging"
error_message = "Process uses anti-debugging technique to block debugger"
*/

std::shared_ptr<sec_analyzer> sec_analyzer::create_sec_analyzer_with_default_rules(void)
{
  return create_sec_analyzer_with_additional_rules(std::vector<sec_rule_describe>());
}

std::shared_ptr<sec_analyzer> sec_analyzer::create_sec_analyzer_with_additional_rules(
    const std::vector<sec_rule_describe> &rules)
{
  std::vector<sec_rule_describe> all_rules;
  for (auto &rule : default_rules)
  {
    all_rules.push_back(rule);
  }
  all_rules.insert(all_rules.end(), rules.begin(), rules.end());
  return std::make_shared<sec_analyzer>(all_rules);
}

std::shared_ptr<sec_analyzer> sec_analyzer_prometheus::create_sec_analyzer_with_default_rules(prometheus_server &server)
{
  return create_sec_analyzer_with_additional_rules(std::vector<sec_rule_describe>(), server);
}

std::shared_ptr<sec_analyzer> sec_analyzer_prometheus::create_sec_analyzer_with_additional_rules(
    const std::vector<sec_rule_describe> &rules,
    prometheus_server &server)
{
  std::vector<sec_rule_describe> all_rules;
  for (auto &rule : default_rules)
  {
    all_rules.push_back(rule);
  }
  all_rules.insert(all_rules.end(), rules.begin(), rules.end());
  return std::make_shared<sec_analyzer_prometheus>(server, all_rules);
}
