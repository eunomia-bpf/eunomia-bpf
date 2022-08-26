#ifndef HTTP_EUNOMIA_H
#define HTTP_EUNOMIA_H

#include "ecli/ecli_core.h"
#include "httplib.h"

/// eunomia http control API server
class eunomia_server
{
 private:
  /// add a mutex to serialize the http request
  std::mutex seq_mutex;
  httplib::Server server;
  ecli_core core;
  int port;

 public:
  /// create a server
  eunomia_server(eunomia_config_data& config, int p);
  ~eunomia_server() = default;
  /// start the server
  void serve(void);
};

#endif
