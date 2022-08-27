/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */
#include "eunomia/eunomia-bpf.hpp"

#include <iostream>
#include <thread>

#include "base64.h"
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
  /// create a ebpf program from json str
  eunomia_ebpf_program::eunomia_ebpf_program(const std::string &json_str)
  {
    meta_data.from_json_str(json_str);
  }
  /// load and attach the ebpf program to the kernel
  int eunomia_ebpf_program::run(void)
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

  const std::string &eunomia_ebpf_program::get_program_name(void) const
  {
    return meta_data.ebpf_name;
  }

  int eunomia_ebpf_program::wait_and_export()
  {
    int err;
    exiting = false;
    // help the wait_and_print work with stop correctly in multi-thread
    std::lock_guard<std::mutex> guard(exit_mutex);
    /* Set up ring buffer polling */
    auto id = rb_map_id;
    if (id < 0)
    {
      std::cout << "running and waiting for the ebpf program..." << std::endl;
      // if we don't have a ring buffer, just wait for the program to exit
      while (!exiting)
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      return 0;
    }
    if (check_for_meta_types_and_create_print_format() < 0)
    {
      std::cerr << "Failed to create print format" << std::endl;
      return -1;
    }
    rb = ring_buffer__new(bpf_map__fd(maps[id]), handle_print_ringbuf_event, this, NULL);
    if (!rb)
    {
      fprintf(stderr, "Failed to create ring buffer\n");
      return 0;
    }

    std::cout << "running and waiting for the ebpf events..." << std::endl;
    /* Process events */
    while (!exiting)
    {
      err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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

  void eunomia_ebpf_program::stop_and_clean()
  {
    exiting = true;
    /// wait until poll has exit
    std::lock_guard<std::mutex> guard(exit_mutex);
    if (skeleton)
    {
      bpf_object__destroy_skeleton(skeleton);
    }
    if (rb)
    {
      ring_buffer__free(rb);
    }
  }

  int eunomia_ebpf_program::create_prog_skeleton(void)
  {
    struct bpf_object_skeleton *s;

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

    rb_map_id = -1;
    maps.resize(meta_data.maps.size());
    for (std::size_t i = 0; i < meta_data.maps.size(); i++)
    {
      if (meta_data.maps[i].type == "BPF_MAP_TYPE_UNSPEC")
      {
        // skip unrecognized maps
        continue;
      }
      if (meta_data.maps[i].type == "BPF_MAP_TYPE_RINGBUF")
      {
        rb_map_id = i;
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