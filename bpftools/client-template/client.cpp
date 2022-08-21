extern "C"
{
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

#include "client.skel.h"
}

#include <fstream>

#include "../../include/hot_update_templates/hot_update.h"
#include "../../include/httplib.h"

constexpr auto default_address = "localhost:8527";

int main(int argc, char **argv)
{
  struct client_bpf obj;
  json j;

  if (client_bpf__create_skeleton(&obj))
  {
    return 1;
  }
  if (argc < 2)
  {
    std::cout << bpf_skeleton_encode(obj.skeleton);
    return 0;
  }
  httplib::Client cli(default_address);
  if (strcmp(argv[1], "list") == 0)
  {
    auto req = cli.Get("/list");
    std::cout << req->status << " :" << req->body << std::endl;
    return 0;
  }
  else if (strcmp(argv[1], "stop") == 0)
  {
    if (argc < 3)
    {
      std::cout << "Please specify the id of the program to stop" << std::endl;
      return 1;
    }
    int id = atoi(argv[2]);
    json http_data;
    http_data["id"] = id;
    auto req = cli.Post("/stop", http_data.dump(), "text/plain");
    std::cout << req->status << " :" << req->body << std::endl;
    return 0;
  }
  std::string harg = bpf_skeleton_encode(obj.skeleton);
  json http_data = json::parse(
      "{\
            \"name\": \"hotupdate\",\
            \"export_handlers\": [\
                {\
                    \"name\": \"plain_text\",\
                    \"args\": []\
                }\
            ],\
            \"args\": [\
            ]\
        }");
  http_data["args"].push_back(harg);
  auto req = cli.Post("/start", http_data.dump(), "text/plain");
  std::cout << req->status << " :" << req->body << std::endl;
  return 0;
}
