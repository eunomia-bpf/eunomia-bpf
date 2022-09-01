/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */
#include <iostream>
#include <thread>

#include "base64.h"
#include "eunomia/eunomia-bpf.hpp"
#include "json.hpp"

extern "C"
{
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
}

using json = nlohmann::json;
namespace eunomia
{
  int eunomia_ebpf_program::load_and_attach_prog(void)
  {
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (create_prog_skeleton())
    {
      std::cerr << "Failed to create skeleton from json" << std::endl;
      return -1;
    }
    if (bpf_object__open_skeleton(skeleton, NULL))
    {
      std::cerr << "Failed to open skeleton" << std::endl;
      return -1;
    }

    /* Load & verify BPF programs */
    err = bpf_object__load_skeleton(skeleton);
    if (err)
    {
      std::cerr << "Failed to load skeleton" << std::endl;
      return -1;
    }

    /* Attach tracepoints */
    err = bpf_object__attach_skeleton(skeleton);
    if (err)
    {
      std::cerr << "Failed to attach skeleton" << std::endl;
      return -1;
    }
    return 0;
  }
  /// load and attach the eBPF program to the kernel
  int eunomia_ebpf_program::run(void) noexcept
  {
    // check the state of the program
    if (state == ebpf_program_state::INVALID)
    {
      return -1;
    }
    else if (state == ebpf_program_state::RUNNING)
    {
      return 0;
    }
    int err = 0;
    try
    {
      err = load_and_attach_prog();
    }
    catch (const std::exception &e)
    {
      std::cerr << "Failed to run eBPF program: " << e.what() << std::endl;
      state = ebpf_program_state::INVALID;
    }
    state = ebpf_program_state::RUNNING;
    return err;
  }

  const std::string &eunomia_ebpf_program::get_program_name(void) const
  {
    return meta_data.ebpf_name;
  }

  static int handle_print_ringbuf_event(void *ctx, void *data, size_t data_sz)
  {
    const char *e = (const char *)(const void *)data;
    const eunomia_ebpf_program *p = (const eunomia_ebpf_program *)ctx;
    if (!p || !e)
    {
      std::cerr << "empty ctx or events" << std::endl;
      return -1;
    }
    p->handler_export_events(e);
    return 0;
  }

  int eunomia_ebpf_program::wait_and_poll_from_rb(std::size_t rb_map_id)
  {
    int err = 0;

    std::cout << "running and waiting for the ebpf events from ring buffer..." << std::endl;
    if (check_for_meta_types_and_create_export_format(meta_data.maps[rb_map_id].export_data_types) < 0)
    {
      std::cerr << "Failed to create print format" << std::endl;
      return -1;
    }
    ring_buffer_map = ring_buffer__new(bpf_map__fd(maps[rb_map_id]), handle_print_ringbuf_event, this, NULL);
    if (!ring_buffer_map)
    {
      fprintf(stderr, "Failed to create ring buffer\n");
      return 0;
    }

    /* Process events */
    while (!exiting)
    {
      err = ring_buffer__poll(ring_buffer_map, config_data.poll_timeout_ms);
      /* Ctrl-C will cause -EINTR */
      if (err == -EINTR)
      {
        err = 0;
        break;
      }
      if (err < 0)
      {
        printf("Error polling perf buffer: %d\n", err);
        return -1;
      }
    }
    return 0;
  }

  static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
  {
    const char *e = (const char *)(const void *)data;
    const eunomia_ebpf_program *p = (const eunomia_ebpf_program *)ctx;
    if (!p || !e)
    {
      std::cerr << "empty ctx or events" << std::endl;
      return;
    }
    p->handler_export_events(e);
  }

  static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
  {
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
  }

  int eunomia_ebpf_program::wait_and_poll_from_perf_event(std::size_t rb_map_id)
  {
    int err = 0;

    std::cout << "running and waiting for the ebpf events from perf event..." << std::endl;
    if (check_for_meta_types_and_create_export_format(meta_data.maps[rb_map_id].export_data_types) < 0)
    {
      std::cerr << "Failed to create print format" << std::endl;
      return -1;
    }
    /* setup event callbacks */
    perf_buffer_map = perf_buffer__new(
        bpf_map__fd(maps[rb_map_id]), config_data.perf_buffer_pages, handle_event, handle_lost_events, this, NULL);
    if (!perf_buffer_map)
    {
      err = -errno;
      fprintf(stderr, "failed to open perf buffer: %d\n", err);
      return err;
    }

    /* main: poll */
    while (!exiting)
    {
      err = perf_buffer__poll(perf_buffer_map, config_data.poll_timeout_ms);
      if (err < 0 && err != -EINTR)
      {
        fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
        return err;
      }
      /* reset err to return 0 if exiting */
      err = 0;
    }
    return 0;
  }

  int eunomia_ebpf_program::wait_for_no_export_program(void)
  {
    std::cout << "running and waiting for the ebpf program..." << std::endl;
    // if we don't have a ring buffer, just wait for the program to exit
    while (!exiting)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
  }

  int eunomia_ebpf_program::check_export_maps(void)
  {
    for (std::size_t i = 0; i < meta_data.maps.size(); i++)
    {
      auto &map = meta_data.maps[i];
      if (map.type == "BPF_MAP_TYPE_RINGBUF")
      {
        return wait_and_poll_from_rb(i);
      }
      else if (map.type == "BPF_MAP_TYPE_PERF_EVENT_ARRAY")
      {
        return wait_and_poll_from_perf_event(i);
      }
    }
    return wait_for_no_export_program();
  }

  int eunomia_ebpf_program::enter_wait_and_export(void)
  {
    int err;
    exiting = false;
    // check the state
    if (state != ebpf_program_state::RUNNING)
    {
      std::cerr << "ebpf program is not running" << std::endl;
      return -1;
    }
    // help the wait_and_print work with stop correctly in multi-thread
    std::lock_guard<std::mutex> guard(exit_mutex);
    return check_export_maps();
  }

  int eunomia_ebpf_program::wait_and_export(void) noexcept
  {
    user_export_event_handler =
        std::bind(&eunomia_ebpf_program::print_default_export_event_with_time, this, std::placeholders::_1);
    int err = 0;
    try
    {
      err = enter_wait_and_export();
    }
    catch (const std::exception &e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      err = -1;
    }
    return err;
  }

  void eunomia_ebpf_program::stop_and_clean() noexcept
  {
    if (state != ebpf_program_state::RUNNING)
    {
      return;
    }
    exiting = true;
    /// wait until poll has exit
    std::lock_guard<std::mutex> guard(exit_mutex);
    // TODO: fix this with smart ptr
    bpf_object__destroy_skeleton(skeleton);
    skeleton = nullptr;
    ring_buffer__free(ring_buffer_map);
    ring_buffer_map = nullptr;
    perf_buffer__free(perf_buffer_map);
    perf_buffer_map = nullptr;
    state = ebpf_program_state::STOPPED;
  }

  int eunomia_ebpf_program::create_prog_skeleton(void)
  {
    struct bpf_object_skeleton *s;
    skeleton = nullptr;

    s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
    if (!s)
      return -1;

    s->sz = sizeof(*s);
    s->name = meta_data.ebpf_name.c_str();

    /* maps */
    s->map_cnt = 0;
    s->map_skel_sz = sizeof(*s->maps);
    s->maps = (struct bpf_map_skeleton *)calloc(meta_data.maps.size(), (size_t)s->map_skel_sz);
    if (!s->maps)
      goto err;

    maps.resize(meta_data.maps.size());
    for (std::size_t i = 0; i < meta_data.maps.size(); i++)
    {
      if (meta_data.maps[i].type == "BPF_MAP_TYPE_UNSPEC")
      {
        // skip unrecognized maps
        continue;
      }
      s->maps[s->map_cnt].name = meta_data.maps[i].name.c_str();
      s->maps[s->map_cnt].map = &maps[i];
      s->map_cnt++;
    }

    /* programs */
    s->prog_skel_sz = sizeof(*s->progs);
    s->progs = (struct bpf_prog_skeleton *)calloc(meta_data.progs.size(), (size_t)s->prog_skel_sz);
    if (!s->progs)
      goto err;
    progs.resize(meta_data.progs.size());
    links.resize(meta_data.progs.size());
    s->prog_cnt = 0;
    for (std::size_t i = 0; i < meta_data.progs.size(); i++)
    {
      s->progs[s->prog_cnt].name = meta_data.progs[i].name.c_str();
      s->progs[s->prog_cnt].prog = &progs[i];
      s->progs[s->prog_cnt].link = &links[i];
      s->prog_cnt++;
    }

    s->data_sz = meta_data.data_sz;
    base64_decode_buffer = base64_decode((const unsigned char *)meta_data.ebpf_data.c_str(), meta_data.ebpf_data.size());
    s->data = (void *)base64_decode_buffer.data();

    s->obj = &obj;
    skeleton = s;
    return 0;
  err:
    bpf_object__destroy_skeleton(s);
    return -1;
  }

}  // namespace eunomia

// simple wrappers for C API
extern "C"
{
  struct eunomia_bpf
  {
    struct eunomia::eunomia_ebpf_program program;
  };
  struct eunomia_bpf *create_ebpf_program_from_json(const char *json_data)
  {
    return new eunomia_bpf{ eunomia::eunomia_ebpf_program(json_data) };
  }

  int run_ebpf_program(struct eunomia_bpf *prog)
  {
    if (!prog)
    {
      return -1;
    }
    return prog->program.run();
  }

  int wait_and_export_ebpf_program(struct eunomia_bpf *prog)
  {
    if (!prog)
    {
      return -1;
    }
    return prog->program.wait_and_export();
  }

  void stop_and_clean_ebpf_program(struct eunomia_bpf *prog)
  {
    if (!prog)
    {
      return;
    }
    prog->program.stop_and_clean();
    delete prog;
  }
}