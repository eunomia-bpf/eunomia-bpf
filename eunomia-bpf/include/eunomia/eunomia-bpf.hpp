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
    /// create a ebpf program from json config str
    eunomia_ebpf_program(const std::string &json_str);
    eunomia_ebpf_program(const eunomia_ebpf_program &) = delete;
    eunomia_ebpf_program(eunomia_ebpf_program &&) = delete;
    ~eunomia_ebpf_program()
    {
      stop_and_clean();
    }
    /// start running the ebpf program

    /// load and attach the ebpf program to the kernel to run the ebpf program
    /// if the ebpf program has maps to export to user space, you need to call
    /// the wait and export.
    int run(void);

    /// wait for the program to exit

    /// if the program has a ring buffer or perf event to export data
    /// to user space, the program will help load the map info and poll the
    /// events automatically.
    int wait_and_export(void);

    /// stop, detach, and clean up memory

    /// This is thread safe with wait_and_export.
    /// it will notify the wait_and_export to exit and
    /// wait until it exits.
    void stop_and_clean(void);

    /// get the name id of the ebpf program
    const std::string &get_program_name(void) const;

    /// print event with meta data;
    void print_event_with_default_types(const char *event) const;
  };

  int handle_print_ringbuf_event(void *ctx, void *data, size_t data_sz);
}  // namespace eunomia

#endif
