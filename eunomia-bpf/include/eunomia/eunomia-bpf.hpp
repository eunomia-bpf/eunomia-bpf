/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, Yusheng Zheng
 * All rights reserved.
 */
#ifndef EUNOMIA_BPF_HPP_
#define EUNOMIA_BPF_HPP_

#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#include "eunomia-config.hpp"
#include "eunomia-meta.hpp"
#include "export-events.hpp"
#include "processor.hpp"

struct bpf_map;
struct bpf_program;
struct bpf_link;
struct bpf_object_skeleton;
struct ring_buffer;
struct bpf_object;
struct perf_buffer;

namespace eunomia
{
  enum class ebpf_program_state
  {
    /// @brief The config is set but the program is not loaded
    INIT,
    /// @brief The program is loaded and attached to the kernel
    RUNNING,
    /// @brief  The program is stopped
    STOPPED,
    /// @brief invalid format or cannot be load
    INVALID
  };

  /// @brief eunomia-bpf program class

  /// @details Used for managing the life span of eBPF program
  class eunomia_ebpf_program
  {
   friend class eunomia_raw_processor;
   private:
    /// create an ebpf skeleton
    int create_prog_skeleton(void);

    int load_and_attach_prog(void);

    /// wait and polling the ring buffer map
    int wait_and_poll_from_rb(std::size_t id);
    /// wait and polling from perf event
    int wait_and_poll_from_perf_event(std::size_t id);
    /// simply wait for the program to exit
    /// use in no export data mode
    int wait_for_no_export_program(void);
    /// check and decide the map to export data from
    int check_export_maps(void);
    /// called after setting the export handler
    int enter_wait_and_export(void);

   private:
    /// The state of eunomia-bpf program
    ebpf_program_state state = ebpf_program_state::INVALID;
    /// is the polling ring buffer loop exiting?
    std::mutex exit_mutex = {};
    volatile bool exiting = false;
    /// @brief  data storage
    /// @details meta data control the behavior of ebpf program:
    /// eg. types of the eBPF maps and prog, export data types
    eunomia_ebpf_meta_data meta_data;
    /// @brief  config of eunomia own
    /// @details config of eunomia own,
    /// for how we creating, loading and interacting with the eBPF program
    /// eg. poll maps timeout in ms
    eunomia_config config_data;

    /// @brief  controler of the export event to user space
    eunomia_event_exporter event_exporter;

    // use lua or wasm to help process the eBPF program in every state
    eunomia_raw_processor processor = {};

    /// buffer to base 64 decode
    bpf_object *obj = nullptr;
    std::vector<char> base64_decode_buffer = {};
    std::vector<bpf_map *> maps = {};
    std::vector<bpf_program *> progs = {};
    std::vector<bpf_link *> links = {};
    char* bss_buffer = nullptr;
    char* rodata_buffer = nullptr;
    bpf_object_skeleton *skeleton = nullptr;

    /// used for processing maps and free them
    // FIXME: use smart pointer instead of raw pointer
    ring_buffer *ring_buffer_map = nullptr;
    perf_buffer *perf_buffer_map = nullptr;

   public:
    /// create a ebpf program from json config str
    eunomia_ebpf_program(const std::string &json_str);
    eunomia_ebpf_program() = default;
    [[nodiscard]] int load_json_config(const std::string &json_str) noexcept;
    eunomia_ebpf_program(const eunomia_ebpf_program &) = delete;
    eunomia_ebpf_program(eunomia_ebpf_program &&);
    ~eunomia_ebpf_program()
    {
      stop_and_clean();
    }
    /// start running the ebpf program

    /// load and attach the ebpf program to the kernel to run the ebpf program
    /// if the ebpf program has maps to export to user space, you need to call
    /// the wait and export.
    [[nodiscard]] int run(void) noexcept;

    /// @brief wait for the program to exit
    /// @details the program has a ring buffer or perf event to export data
    /// to user space, the program will help load the map info and poll the
    /// events automatically.
    [[nodiscard]] int wait_and_export(void) noexcept;
    /// @brief export the data as json string.
    /// @details The key of the value is the field name in the export json.
    [[nodiscard]] int
    wait_and_export_to_handler(enum export_format_type type, export_event_handler handler, void *ctx = nullptr) noexcept;

    /// stop, detach, and clean up memory

    /// This is thread safe with wait_and_export.
    /// it will notify the wait_and_export to exit and
    /// wait until it exits.
    void stop_and_clean(void) noexcept;

    /// get the name id of the ebpf program
    const std::string &get_program_name(void) const;

    /// @brief  event with meta data;
    /// @details  for export call backs: ring buffer and perf events
    /// provide a common interface to print the event data
    void handler_export_events(const char *event) const;
  };
}  // namespace eunomia

#endif
