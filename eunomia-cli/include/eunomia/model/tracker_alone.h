/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef TRACKER_ALONE_H
#define TRACKER_ALONE_H

#include <vector>

#include "tracker.h"

/// the tracker alone config env
struct tracker_alone_env
{
  volatile bool *exiting;
  /// wait for the child process to write in the pipe

  /// the buffer will collect result for us
  /// avoid busy reading short buffer
  int wait_ms_for_read;
  /// The main func
  typedef int (*start_func)(int argc, char **argv);
  /// the main func
  start_func main_func;
  std::vector<std::string> process_args;
};

/// The single process tracker reported event
struct tracker_alone_event
{
  /// pid for the event
  int pid;
  /// the message for the event

  /// note this may be multi-line
  std::string process_messages;
};

// Run tracker as a standalone process, and communicate with pipe
struct tracker_alone_base : public tracker_with_config<tracker_alone_env, tracker_alone_event>
{
 private:
  /// message buffer size for the event
  constexpr static int MAX_PROCESS_MESSAGE_LENGTH = 1024 * 1024 * 4;
  pid_t child_pid;
  /// the pipe for communication
  int stdout_pipe_fd[2];
  char stdout_pipe_buf[MAX_PROCESS_MESSAGE_LENGTH];
  /// start child process for running ebpf program
  void start_child_process();
  /// start parent process for event handler
  void start_parent_process();

  /// handle readed data from pipe
  int handle_message_event(std::string&& event);

 public:
  tracker_alone_base(config_data config);
  ~tracker_alone_base();

  /// start the separated process
  void start_tracker();

  /// create a tracker with config
  static std::unique_ptr<tracker_alone_base> create_tracker_with_default_env(tracker_event_handler handler);

  /// print to stdout
  struct plain_text_event_printer final : public event_handler<tracker_alone_event>
  {
    void handle(tracker_event<tracker_alone_event> &e);
  };
};

#endif
