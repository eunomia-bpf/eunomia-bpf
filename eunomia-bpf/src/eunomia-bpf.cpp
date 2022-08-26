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

/// use as a optional field
/// if the field exists, we get it.
#define get_opt_from_json_at(name) \
  do                               \
  {                                \
    json res;                      \
    try                            \
    {                              \
      res = j.at(#name);           \
    }                              \
    catch (...)                    \
    {                              \
      break;                       \
    }                              \
    res.get_to(data.name);         \
  } while (0);

/// get from json
/// throw an error if get failed.
#define get_from_json_at(name)     \
  {                                \
    j.at(#name).get_to(data.name); \
  }

static void from_json(const nlohmann::json &j, ebpf_rb_export_field_meta_data &data)
{
  j.at("Name").get_to(data.name);
  j.at("Type").get_to(data.type);
  j.at("FieldOffset").get_to(data.field_offset);
  j.at("LLVMType").get_to(data.llvm_type);
}

static void from_json(const nlohmann::json &j, ebpf_rb_export_meta_data &data)
{
  j.at("Alignment").get_to(data.alignment);
  j.at("DataSize").get_to(data.data_size);
  j.at("Size").get_to(data.size);
  j.at("Struct Name").get_to(data.struct_name);
  j.at("Fields").get_to(data.fields);
}

static void from_json(const nlohmann::json &j, ebpf_progs_meta_data &data)
{
  get_from_json_at(name);
  get_opt_from_json_at(type);
}

static void from_json(const nlohmann::json &j, ebpf_maps_meta_data &data)
{
  get_from_json_at(name);
  get_from_json_at(type);
  get_opt_from_json_at(ring_buffer_export);
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
  rb = ring_buffer__new(bpf_map__fd(maps[id]), handle_print_event, this, NULL);
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

#define print_not_zero(format, value) \
  do                                  \
  {                                   \
    if (value)                        \
      printf(format, value);          \
  } while (false)

struct print_type_format_map
{
  const char *format;
  const char *type_str;
  const char *llvm_type_str;
};

static print_type_format_map base_type_look_up_table[] = {
    {"%d", "int", "i32"},
    {"%lld", "long long", "i64"},
    {"%u", "unsigned int", "i32"},
    {"%llu", "unsigned long long", "i64"},
    {"%d", "unsigned char", "i8"},
    {"%c", "char", "i8"},
    {"%c", "_Bool", "i8"},
    // Support more types?
};

int eunomia_ebpf_program::check_for_meta_types_and_create_print_format(void)
{
  auto fields = meta_data.maps[rb_map_id].ring_buffer_export.fields;
  for (std::size_t i = 0; i < fields.size(); ++i)
  {
    auto &field = fields[i];
    std::size_t width = 0;
    // calculate width of a field
    if (i < fields.size() - 1)
    {
      width = fields[i + 1].field_offset - field.field_offset;
    }
    else
    {
      width = meta_data.maps[rb_map_id].ring_buffer_export.data_size - field.field_offset;
    }
    // use the byte number instead of the width
    width /= 8;
    // use the lookup table to determine format
    for (auto &type : base_type_look_up_table)
    {
      if (field.type == type.type_str || field.llvm_type == type.llvm_type_str)
      {
        print_rb_default_format.push_back({type.format, field.field_offset, width});
        break;
      }
      else if (field.llvm_type.size() > 0)
      {
        if (field.llvm_type.front() == '[' && field.type.size() > 4 && std::strncmp(field.type.c_str(), "char", 4) == 0)
        {
          // maybe a char array: fix this
          print_rb_default_format.push_back({"%s", field.field_offset, width});
          break;
        }
      }
    }
  }
  if (print_rb_default_format.size() == 0)
  {
    std::cout << "No available format type!" << std::endl;
    return -1;
  }
  return 0;
}

template <typename T>
static void print_rb_field(const char *data, const eunomia_ebpf_program::format_info &f)
{
  printf(f.print_fmt, *(T *)(data + f.field_offset / 8));
  printf(" ");
}

static const std::map<std::size_t, std::function<void(const char *data, const eunomia_ebpf_program::format_info &f)>>
    print_func_lookup_map = {
        {1, print_rb_field<uint8_t>},
        {2, print_rb_field<uint16_t>},
        {4, print_rb_field<uint32_t>},
        {8, print_rb_field<uint64_t>},
};

void eunomia_ebpf_program::print_rb_event(const char *event) const
{
  struct tm *tm;
  char ts[32];
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);
  printf("%-8s ", ts);
  for (const auto &f : print_rb_default_format)
  {
    auto func = print_func_lookup_map.find(f.width);
    if (func != print_func_lookup_map.end())
    {
      func->second((const char *)event, f);
    }
    else
    {
      // should be an array
      printf("%s ", (char *)(event + f.field_offset / 8));
    }
  }
  printf("\n");
}

static int handle_print_event(void *ctx, void *data, size_t data_sz)
{
  const char *e = (const char *)(const void *)data;
  const eunomia_ebpf_program *p = (const eunomia_ebpf_program *)ctx;
  if (!p && !e)
    return -1;
  p->print_rb_event(e);
  return 0;
}
