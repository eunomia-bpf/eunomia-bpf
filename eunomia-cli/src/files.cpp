/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#include "eunomia/files.h"

#include <spdlog/spdlog.h>

#include <json.hpp>

using json = nlohmann::json;

void files_tracker::prometheus_event_handler::report_prometheus_event(const struct files_event &e)
{
  for (size_t i = 0; i < e.rows; i++)
  {
    auto pid = e.values[i].pid;
    auto container_info = container_manager_ref.get_container_info_for_pid(pid);
    auto pid_str = std::to_string(e.values[i].pid);
    auto file_name_str = std::string(e.values[i].filename);
    auto comm_str = std::string(e.values[i].comm);
    auto type_str = std::to_string(e.values[i].type);

    eunomia_files_write_counter
        .Add({ { "type", type_str },
               { "filename", file_name_str },
               { "comm", comm_str },
               { "container_id", container_info.id },
               { "container_name", container_info.name },
               { "pid", pid_str } })
        .Increment((double)e.values[i].writes);
    eunomia_files_read_counter
        .Add({
            { "comm", comm_str },
            { "container_id", container_info.id },
            { "container_name", container_info.name },
            { "filename", file_name_str },
            { "pid", pid_str },
            { "type", type_str },
        })
        .Increment((double)e.values[i].reads);
    eunomia_files_write_bytes
        .Add({ { "type", type_str },
               { "container_id", container_info.id },
               { "container_name", container_info.name },
               { "filename", file_name_str },
               { "comm", comm_str },
               { "pid", pid_str } })
        .Increment((double)e.values[i].write_bytes);
    eunomia_files_read_bytes
        .Add({
            { "comm", comm_str },
            { "container_id", container_info.id },
            { "container_name", container_info.name },
            { "filename", file_name_str },
            { "pid", pid_str },
            { "type", type_str },
        })
        .Increment((double)e.values[i].read_bytes);
  }
}

files_tracker::prometheus_event_handler::prometheus_event_handler(prometheus_server &server)
    : eunomia_files_read_counter(prometheus::BuildCounter()
                                     .Name("eunomia_observed_files_read_count")
                                     .Help("Number of observed files read count")
                                     .Register(*server.registry)),
      eunomia_files_write_counter(prometheus::BuildCounter()
                                      .Name("eunomia_observed_files_write_count")
                                      .Help("Number of observed files write count")
                                      .Register(*server.registry)),
      eunomia_files_write_bytes(prometheus::BuildCounter()
                                    .Name("eunomia_observed_files_write_bytes")
                                    .Help("Number of observed files write bytes")
                                    .Register(*server.registry)),
      eunomia_files_read_bytes(prometheus::BuildCounter()
                                   .Name("eunomia_observed_files_read_bytes")
                                   .Help("Number of observed files read bytes")
                                   .Register(*server.registry)),
      container_manager_ref(server.core_container_manager_ref)
{
}

void files_tracker::prometheus_event_handler::handle(tracker_event<files_event> &e)
{
  report_prometheus_event(e.data);
}

files_tracker::files_tracker(config_data config) : tracker_with_config(config)
{
  exiting = false;
  this->current_config.env.exiting = &exiting;
}

std::unique_ptr<files_tracker> files_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "files_tracker";
  config.env = files_env{
    .target_pid = 0,
    .clear_screen = false,
    .regular_file_only = true,
    .output_rows = OUTPUT_ROWS_LIMIT,
    .sort_by = ALL,
    .interval = 3,
    .count = 99999999,
    .verbose = false,
  };
  return std::make_unique<files_tracker>(config);
}

void files_tracker::start_tracker()
{
  struct files_bpf *skel = nullptr;
  // start_files_tracker(handle_event, libbpf_print_fn, current_config.env,
  // skel, (void *)this);
  current_config.env.ctx = (void *)this;
  start_file_tracker(handle_tracker_event<files_tracker, files_event>, libbpf_print_fn, current_config.env);
}

std::string files_tracker::json_event_handler::to_json(const struct files_event &e)
{
  std::string res;
  json files = { { "type", "process" }, { "time", get_current_time() } };
  json files_event_json = json::array();
  for (size_t i = 0; i < e.rows; i++)
  {
    files_event_json.push_back({ { "pid", e.values[i].pid },
                                 { "read_bytes", e.values[i].read_bytes },
                                 { "reads", e.values[i].reads },
                                 { "write_bytes", e.values[i].write_bytes },
                                 { "writes", e.values[i].writes },
                                 { "comm", e.values[i].comm },
                                 { "filename", e.values[i].filename },
                                 { "type", e.values[i].type },
                                 { "tid", e.values[i].tid } });
  }
  files.push_back({ "files", files_event_json });
  return files.dump();
}

void files_tracker::json_event_printer::handle(tracker_event<files_event> &e)
{
  std::cout << to_json(e.data) << std::endl;
}

static int sort_column(const void *obj1, const void *obj2)
{
  struct file_stat *s1 = (struct file_stat *)obj1;
  struct file_stat *s2 = (struct file_stat *)obj2;

  return (int)(-(
      (s2->reads + s2->writes + s2->read_bytes + s2->write_bytes) -
      (s1->reads + s1->writes + s1->read_bytes + s1->write_bytes)));
}

void files_tracker::plain_text_event_printer::handle(tracker_event<files_event> &e)
{
  static const int default_size = 20;
  int res = std::system("clear");
  qsort(e.data.values, e.data.rows, sizeof(struct file_stat), sort_column);
  spdlog::info(
      "{:6} {:10} {:6} {:6} {:10} {:10} {:6} {:12} {:12}",
      "pid",
      "container_name",
      "reads",
      "writes",
      "read_bytes",
      "write_bytes",
      "type",
      "comm",
      "filename");
  for (int i = 0; i < default_size; i++)
  {
    spdlog::info(
        "{:6} {:10} {:6} {:6} {:10} {:10} {:6} {:12} {:12}",
        e.data.values[i].pid,
        "ubuntu",
        e.data.values[i].reads,
        e.data.values[i].writes,
        e.data.values[i].read_bytes,
        e.data.values[i].write_bytes,
        e.data.values[i].type,
        e.data.values[i].comm,
        e.data.values[i].filename);
  }
}

void files_tracker::csv_event_printer::handle(tracker_event<files_event> &e)
{
  static bool is_start = true;
  if (is_start)
  {
    is_start = false;
    std::cout << "pid,read_bytes,read_count,write_bytes,write "
                 "count,comm,type,tid,filename"
              << std::endl;
  }
  for (size_t i = 0; i < e.data.rows; i++)
  {
    std::cout << e.data.values[i].pid << "," << e.data.values[i].read_bytes << "," << e.data.values[i].reads << ","
              << e.data.values[i].write_bytes << "," << e.data.values[i].writes << "," << e.data.values[i].comm << ","
              << e.data.values[i].type << "," << e.data.values[i].tid << "," << e.data.values[i].filename << std::endl;
  }
}
