/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */
#ifndef EUNOMIA_BPF_H
#define EUNOMIA_BPF_H

#include <iostream>
#include <string>
#include <vector>

/// meta data
struct eunomia_ebpf_meta_data
{
  // ebpf name
  std::string ebpf_name;
  std::vector<std::string> maps_names;
  std::vector<std::string> progs_names;
  size_t data_sz;
  std::string ebpf_data;

  std::string to_json_str();
  void from_json_str(const std::string &j_str);
};

struct bpf_map;
struct bpf_program;
struct bpf_link;
struct bpf_object_skeleton;

struct eunomia_ebpf_program {
  bool exiting;
  eunomia_ebpf_meta_data meta_data;

  /// buffer to base 64 decode
  struct bpf_object *obj;
  std::vector<char> base64_decode_buffer;
  std::vector<struct bpf_map *> maps;
  std::vector<struct bpf_program *> progs;
  std::vector<struct bpf_link *> links;
  struct bpf_object_skeleton *skeleton;
  struct ring_buffer *rb = NULL;
};

std::string bpf_skeleton_encode_json(const struct bpf_object_skeleton *skeleton);

int open_ebpf_program_from_json(struct eunomia_ebpf_program &ebpf_program,const std::string &json_str);
int run_ebpf_program(struct eunomia_ebpf_program &ebpf_program);
void stop_ebpf_program(struct eunomia_ebpf_program &ebpf_program);

#endif
