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
#include <mutex>

struct ebpf_rb_export_field_meta_data
{
  std::string name;
  std::string type;
  std::string llvm_type;
  uint32_t field_offset;
};

struct ebpf_rb_export_meta_data
{
  std::vector<ebpf_rb_export_field_meta_data> fields;
  std::string struct_name;
  uint32_t size;
  uint32_t data_size;
  uint32_t alignment;
};

struct ebpf_maps_meta_data
{
  std::string name;
  std::string type;
  ebpf_rb_export_meta_data ring_buffer_export;
};

struct ebpf_progs_meta_data
{
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
  int check_for_meta_types_and_create_print_format(void);

private:
  /// is the polling ring buffer loop exiting?
  std::mutex exit_mutex;
  volatile bool exiting;
  /// meta data storage
  eunomia_ebpf_meta_data meta_data;

  /// buffer to base 64 decode
  struct bpf_object *obj;
  std::vector<char> base64_decode_buffer;
  std::vector<struct bpf_map *> maps;
  std::vector<struct bpf_program *> progs;
  std::vector<struct bpf_link *> links;
  struct bpf_object_skeleton *skeleton;

  int rb_map_id = -1;
  struct ring_buffer *rb = NULL;

public:
  /// create a ebpf program from json str
  eunomia_ebpf_program(const std::string &json_str);
  eunomia_ebpf_program(const eunomia_ebpf_program &) = delete;
  eunomia_ebpf_program(eunomia_ebpf_program &&) = delete;
  ~eunomia_ebpf_program()
  {
    stop_and_clean();
  }
  /// load and attach the ebpf program to the kernel
  int run(void);
  /// wait and print the messages from te ring buffer
  int wait_and_print_rb(void);
  /// stop, detach, and clean up memory
  /// This is thread safe with ring buffer.
  void stop_and_clean(void);

  /// get the name id of the ebpf program
  const std::string &get_program_name(void) const;

  // format data
  struct format_info
  {
    const char *print_fmt;
    std::size_t field_offset;
    std::size_t width;
  };
  std::vector<format_info> print_rb_default_format;
  /// print event with meta data;
  void print_rb_event(const char *event) const;
};

#endif
