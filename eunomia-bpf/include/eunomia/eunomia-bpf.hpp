/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, Yusheng Zheng
 * All rights reserved.
 */
#ifndef EUNOMIA_BPF_HPP_
#define EUNOMIA_BPF_HPP_

#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#include "eunomia-meta.hpp"

struct bpf_map;
struct bpf_program;
struct bpf_link;
struct bpf_object_skeleton;
struct ring_buffer;
struct bpf_object;

namespace eunomia
{
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
    bpf_object *obj;
    std::vector<char> base64_decode_buffer;
    std::vector<bpf_map *> maps;
    std::vector<bpf_program *> progs;
    std::vector<bpf_link *> links;
    bpf_object_skeleton *skeleton;

    int rb_map_id = -1;
    ring_buffer *rb = NULL;

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
    void print_event_with_default_types(const char *event) const;
  };

  int handle_print_ringbuf_event(void *ctx, void *data, size_t data_sz);

}  // namespace eunomia

#endif
