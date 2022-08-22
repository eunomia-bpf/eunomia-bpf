/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, Yusheng Zheng
 * All rights reserved.
 */
#ifndef EUNOMIA_BPF_H
#define EUNOMIA_BPF_H

#include <iostream>
#include <string>
#include <vector>

struct ebpf_maps_meta_data {
  std::string name;
  std::string type;
};

struct ebpf_progs_meta_data {
  std::string name;
  std::string type;
};

/// meta data
struct eunomia_ebpf_meta_data
{
  // ebpf name
  std::string ebpf_name;
  std::vector<ebpf_maps_meta_data> maps;
  std::vector<ebpf_progs_meta_data> progs;
  size_t data_sz;
  std::string ebpf_data;

  std::string to_json_str();
  void from_json_str(const std::string &j_str);
};

struct bpf_map;
struct bpf_program;
struct bpf_link;
struct bpf_object_skeleton;

class eunomia_ebpf_program
{
private:
  /// create an ebpf skeleton
  int create_prog_skeleton(void);

private:
  /// is the polling ring buffer loop exiting?
  bool exiting;
  /// meta data storage
  eunomia_ebpf_meta_data meta_data;

  /// buffer to base 64 decode
  struct bpf_object *obj;
  std::vector<char> base64_decode_buffer;
  std::vector<struct bpf_map *> maps;
  std::vector<struct bpf_program *> progs;
  std::vector<struct bpf_link *> links;
  struct bpf_object_skeleton *skeleton;
  struct ring_buffer *rb = NULL;

public:
  /// create a ebpf program from json str
  eunomia_ebpf_program(const std::string &json_str);
  eunomia_ebpf_program(const eunomia_ebpf_program &) = delete;
  eunomia_ebpf_program(eunomia_ebpf_program &&) = delete;
  ~eunomia_ebpf_program()
  {
    stop();
  }
  /// load and attach the ebpf program to the kernel
  int run(void);
  /// wait and print the messages from te ring buffer
  int wait_and_print_rb(void);
  /// stop and detach
  void stop(void);
};

int open_ebpf_program_from_json(struct eunomia_ebpf_program &ebpf_program, const std::string &json_str);
int run_ebpf_program(struct eunomia_ebpf_program &ebpf_program);
void stop_ebpf_program(struct eunomia_ebpf_program &ebpf_program);

#endif
