/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */
#include "eunomia-bpf.h"

#include <iostream>
#include <thread>

#include "base64.h"
#include "event.h"
#include "json.hpp"

extern "C"
{
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
}

using json = nlohmann::json;

static void from_json(const nlohmann::json &j, ebpf_progs_meta_data &data)
{
  j.at("name").get_to(data.name);
  j.at("type").get_to(data.type);
}

static void from_json(const nlohmann::json &j, ebpf_maps_meta_data &data)
{
  j.at("name").get_to(data.name);
  j.at("type").get_to(data.type);
}

void eunomia_ebpf_meta_data::from_json_str(const std::string &j_str)
{
  json jj = json::parse(j_str);
  ebpf_name = jj["name"];
  maps = jj["maps"];
  progs = jj["progs"];
  data_sz = jj["data_sz"];
  ebpf_data = jj["data"];
}

static int handle_print_event(void *ctx, void *data, size_t data_sz);

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

int eunomia_ebpf_program::get_ring_buffer_id(void)
{
  for (std::size_t id = 0; id < maps.size(); id++)
  {
    if (meta_data.maps[id].type == "BPF_MAP_TYPE_RINGBUF")
    {
      return id;
    }
  }
  return -1;
}

const std::string &eunomia_ebpf_program::get_program_name(void) const
{
  return meta_data.ebpf_name;
}

int eunomia_ebpf_program::wait_and_print_rb()
{
  int err;
  exiting = false;
  // help the wait_and_print_rb work with stop correctly in multi-thread
  std::lock_guard<std::mutex> guard(exit_mutex);
  /* Set up ring buffer polling */
  auto id = get_ring_buffer_id();
  if (id < 0) {
    while (!exiting) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return -1;
  }
  rb = ring_buffer__new(bpf_map__fd(maps[id]), handle_print_event, NULL, NULL);
  if (!rb)
  {
    fprintf(stderr, "Failed to create ring buffer\n");
    return -1;
  }

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

  maps.resize(meta_data.maps.size());
  for (std::size_t i = 0; i < meta_data.maps.size(); i++)
  {
    // FIXME: skip rodata
    if (meta_data.maps[i].type == "RODATA")
    {
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

#define print_not_zero(format, value) \
  do                                  \
  {                                   \
    if (value)                        \
      printf(format, value);          \
  } while (false)

static int handle_print_event(void *ctx, void *data, size_t data_sz)
{
  const struct event *e = (const struct event *)data;
  struct tm *tm;
  char ts[32];
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);
  printf("%-8s", ts);
  print_not_zero("%-7d ", e->pid);
  print_not_zero("%-7d ", e->ppid);
  print_not_zero("%s ", e->char_buffer16);
  print_not_zero("%s ", e->char_buffer127);
  print_not_zero("%d ", e->bool_value1);
  print_not_zero("%u ", e->u32_value1);
  print_not_zero("%u ", e->u32_value2);
  print_not_zero("%llu ", e->u64_value1);
  print_not_zero("%llu", e->u64_value2);
  putchar('\n');
  fflush(stdout);
  return 0;
}
