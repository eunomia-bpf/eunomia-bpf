/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef TRACKER_INTEGRATIONS_CMD_H
#define TRACKER_INTEGRATIONS_CMD_H

#include "eunomia/model/tracker_alone.h"
#include "prometheus/counter.h"
#include "prometheus/histogram.h"
#include "prometheus_server.h"

struct oomkill_tracker final : public tracker_alone_base
{
  oomkill_tracker(config_data config) : tracker_alone_base(config)
  {
  }
  static std::unique_ptr<oomkill_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);

  static std::unique_ptr<oomkill_tracker> create_tracker_with_default_env(tracker_event_handler handler);
};

struct tcpconnlat_tracker final : public tracker_alone_base
{
  tcpconnlat_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  struct prometheus_event_handler : public event_handler<tracker_alone_event>
  {
    prometheus::Family<prometheus::Histogram> &eunomia_tcpconnlat_v4_counter;
    prometheus::Family<prometheus::Histogram> &eunomia_tcpconnlat_v6_counter;
    const container_manager &container_manager_ref;

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<tracker_alone_event> &e);
  };

  static std::unique_ptr<tcpconnlat_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<tcpconnlat_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct capable_tracker final : public tracker_alone_base
{
  capable_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  struct prometheus_event_handler : public event_handler<tracker_alone_event>
  {
    prometheus::Family<prometheus::Counter> &eunomia_capable_counter;
    const container_manager &container_manager_ref;

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<tracker_alone_event> &e);
  };

  static std::unique_ptr<capable_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<capable_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct memleak_tracker final : public tracker_alone_base
{
  memleak_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  static std::unique_ptr<memleak_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<memleak_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct mountsnoop_tracker final : public tracker_alone_base
{
  mountsnoop_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  struct prometheus_event_handler : public event_handler<tracker_alone_event>
  {
    prometheus::Family<prometheus::Counter> &eunomia_mountsnoop_counter;
    const container_manager &container_manager_ref;

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<tracker_alone_event> &e);
  };

  static std::unique_ptr<mountsnoop_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<mountsnoop_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct sigsnoop_tracker final : public tracker_alone_base
{
  sigsnoop_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  struct prometheus_event_handler : public event_handler<tracker_alone_event>
  {
    prometheus::Family<prometheus::Counter> &eunomia_sigsnoop_counter;
    const container_manager &container_manager_ref;

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<tracker_alone_event> &e);
  };

  static std::unique_ptr<sigsnoop_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<sigsnoop_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct opensnoop_tracker final : public tracker_alone_base
{
  opensnoop_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  struct prometheus_event_handler : public event_handler<tracker_alone_event>
  {
    prometheus::Family<prometheus::Counter> &eunomia_opensnoop_counter;
    const container_manager &container_manager_ref;

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<tracker_alone_event> &e);
  };

  static std::unique_ptr<opensnoop_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<opensnoop_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct bindsnoop_tracker final : public tracker_alone_base
{
  bindsnoop_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  struct prometheus_event_handler : public event_handler<tracker_alone_event>
  {
    prometheus::Family<prometheus::Counter> &eunomia_bind_counter;
    const container_manager &container_manager_ref;

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<tracker_alone_event> &e);
  };

  static std::unique_ptr<bindsnoop_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<bindsnoop_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct syscount_tracker final : public tracker_alone_base
{
  syscount_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  static std::unique_ptr<syscount_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<syscount_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct funclatency_tracker final : public tracker_alone_base
{
  funclatency_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  static std::unique_ptr<funclatency_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<funclatency_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct tcprtt_tracker final : public tracker_alone_base
{
  tcprtt_tracker(config_data config) : tracker_alone_base(config)
  {
  }

  static std::unique_ptr<tcprtt_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<tcprtt_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);
};

struct hotupdate_tracker final : public tracker_alone_base
{
  hotupdate_tracker(config_data config) : tracker_alone_base(config)
  {
  }
  static std::unique_ptr<hotupdate_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args);

  static std::unique_ptr<hotupdate_tracker> create_tracker_with_default_env(tracker_event_handler handler);
};

#endif
