#ifndef ECLI_SERVER_H
#define ECLI_SERVER_H

#include "httplib.h"
#include "eunomia_runner.h"

/// tracker manager for owning and managing tracker instances

/// provide interface for list, start and exit trackers
/// RAII style
class tracker_manager
{
 private:
  struct tracker_base_data {
    std::string name;
    std::unique_ptr<eunomia_runner> tracker;
  };
  std::size_t id_count = 1;
  std::map<std::size_t,  tracker_base_data> trackers;

 public:
  ~tracker_manager() {
  }
  // remove a tracker with id
  int remove_tracker(std::size_t id)
  {
    if (trackers.erase(id) == 0) {
      return -1;
    }
    return 0;
  }
  // get tracker lists
  // return a list of tracker id and name
  std::vector<std::tuple<int, std::string>> get_tracker_list()
  {
    std::vector<std::tuple<int, std::string>> list;
    for (auto &[id, data] : trackers) {
      list.push_back({id, data.name});
    }
    return list;
  }
  // start a tracker and return id
  std::size_t start_tracker(std::unique_ptr<eunomia_runner> tracker_ptr, const std::string &name)
  {
    if (!tracker_ptr)
    {
      std::cout << "tracker_ptr is null in start_tracker\n";
      return 0;
    }
    std::size_t id = id_count++;
    tracker_ptr->thread = std::thread(&eunomia_runner::start_tracker, tracker_ptr.get());
    trackers.emplace(id, tracker_base_data{name, std::move(tracker_ptr)});
    return id;
  }
  // stop all tracker
  void remove_all_trackers()
  {
    trackers.clear();
  }
};


/// core for building tracker

/// construct tracker with handlers
/// and manage state
struct server_manager
{
 private:
  /// eunomia config
  eunomia_config_data core_config;

  /// manager for all tracker
  tracker_manager core_tracker_manager;

  std::unique_ptr<eunomia_runner> create_default_tracker(tracker_config_data& base);

  /// start all trackers
  std::size_t start_trackers(void);
  /// check and stop all trackers if needed
  void check_auto_exit(std::size_t checker_count);

 public:
  server_manager(eunomia_config_data& config);
  /// start the core
  int start_eunomia(void);
  /// start a single tracker base on config
  std::size_t start_tracker(tracker_config_data& config);
  std::size_t start_tracker(const std::string& json_data);
  /// list all trackers
  std::vector<std::tuple<int, std::string>> list_all_trackers(void);
  /// stop a tracker by id
  void stop_tracker(std::size_t tracker_id);
};


/// eunomia http control API server
class eunomia_server
{
 private:
  /// add a mutex to serialize the http request
  std::mutex seq_mutex;
  httplib::Server server;
  server_manager core;
  int port;

 public:
  /// create a server
  eunomia_server(eunomia_config_data& config, int p);
  ~eunomia_server() = default;
  /// start the server
  void serve(void);
};

#endif
