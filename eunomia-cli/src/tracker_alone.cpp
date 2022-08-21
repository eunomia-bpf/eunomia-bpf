#include "eunomia/model/tracker_alone.h"

#include <spdlog/spdlog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <future>
#include <thread>

void tracker_alone_base::start_child_process()
{
  int res = 0;
  // close unused pipe end
  res = close(stdout_pipe_fd[0]);
  if (res == -1)
  {
    spdlog::error("parent process close pipe failed");
    exit(1);
  }

  // redirect stdout to pipe
  res = dup2(stdout_pipe_fd[1], STDOUT_FILENO);
  if (res == -1)
  {
    spdlog::error("child process dup2 failed");
    exit(1);
  }
  const auto& env = current_config.env;

  std::vector<char*> argv;
  argv.push_back(const_cast<char*>(current_config.name.c_str()));
  spdlog::info("argc: {}", 1 + env.process_args.size());
  for (auto& arg : env.process_args)
  {
    argv.push_back(const_cast<char*>(arg.c_str()));
  }
  argv.push_back(nullptr);
  // start child process ebpf program
  res = env.main_func(static_cast<int>(env.process_args.size() + 1), argv.data());
  // exit child process
  exit(res);
}

void tracker_alone_base::start_parent_process()
{
  int res = 0;
  // close unused pipe end
  res = close(stdout_pipe_fd[1]);
  if (res == -1)
  {
    spdlog::error("parent process close pipe failed");
    return;
  }
  // read from pipe
  ssize_t read_bytes;
  while ((!exiting) && (read_bytes = read(stdout_pipe_fd[0], stdout_pipe_buf, MAX_PROCESS_MESSAGE_LENGTH)) > 0)
  {
    if (handle_message_event(std::string(stdout_pipe_buf, read_bytes)) < 0)
    {
      break;
    }
  }
}

// handle readed data from pipe
int tracker_alone_base::handle_message_event(std::string&& message)
{
  // send to event handler
  auto event = tracker_event<tracker_alone_event>{ 0, message };
  if (current_config.handler)
  {
    current_config.handler->do_handle_event(event);
  }
  else
  {
    std::cout << "warn: no handler for tracker event" << std::endl;
    return -1;
  }
  if (current_config.env.wait_ms_for_read > 0)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(current_config.env.wait_ms_for_read));
  }
  return 0;
}

tracker_alone_base::~tracker_alone_base()
{
  using namespace std::chrono_literals;
  std::future<int> future = std::async(std::launch::async, [=]() {
    // close pipe and clean up
    int res = 0;
    (void)kill(child_pid, SIGINT);
    // wait for thr subprocess to print out the message
    std::this_thread::sleep_for(1s);
    auto read_bytes = read(stdout_pipe_fd[0], stdout_pipe_buf, MAX_PROCESS_MESSAGE_LENGTH);
    if (read_bytes > 0)
    {
      handle_message_event(std::string(stdout_pipe_buf, read_bytes));
    }
    (void)close(stdout_pipe_fd[0]);
    (void)kill(child_pid, SIGKILL);
    res = waitpid(child_pid, nullptr, 0);
    if (res == -1)
    {
      spdlog::error("parent process waitpid failed");
      return -1;
    }
    return 0;
  });

  spdlog::info("waiting for the tracker to cleanup...");
  std::future_status status;
  switch (status = future.wait_for(3s); status)
  {
    case std::future_status::timeout: spdlog::info("timeout\n"); break;
    case std::future_status::ready: spdlog::info("exit!\n"); break;
  }
}

void tracker_alone_base::start_tracker()
{
  int res = 0;
  res = pipe(stdout_pipe_fd);
  if (res < 0)
  {
    spdlog::error("create pipe error");
    return;
  }

  res = fork();
  if (res == 0)
  {
    // child process
    start_child_process();
    assert(false && "The program should not be here");
  }
  else if (res > 0)
  {
    // parent process
    child_pid = res;
    start_parent_process();
  }
  else
  {
    // error
    spdlog::error("fork error");
    close(stdout_pipe_fd[0]);
    close(stdout_pipe_fd[1]);
  }
  spdlog::info("{} tracker exited.", current_config.name);
}

tracker_alone_base::tracker_alone_base(config_data config) : tracker_with_config(config)
{
  exiting = false;
  this->current_config.env.exiting = &exiting;
}

std::unique_ptr<tracker_alone_base> tracker_alone_base::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "process_tracker";
  config.env = tracker_alone_env{ 0 };
  return std::make_unique<tracker_alone_base>(config);
}

void tracker_alone_base::plain_text_event_printer::handle(tracker_event<tracker_alone_event>& e)
{
  std::cout << e.data.process_messages;
}