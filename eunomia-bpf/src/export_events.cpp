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

namespace eunomia
{
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
    { "%d", "int", "i32" },          { "%lld", "long long", "i64" },
    { "%u", "unsigned int", "i32" }, { "%llu", "unsigned long long", "i64" },
    { "%d", "unsigned char", "i8" }, { "%c", "char", "i8" },
    { "%c", "_Bool", "i8" },
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
          print_rb_default_format.push_back({ type.format, field.field_offset, width });
          break;
        }
        else if (field.llvm_type.size() > 0)
        {
          if (field.llvm_type.front() == '[' && field.type.size() > 4 && std::strncmp(field.type.c_str(), "char", 4) == 0)
          {
            // maybe a char array: fix this
            print_rb_default_format.push_back({ "%s", field.field_offset, width });
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

  template<typename T>
  static void print_rb_field(const char *data, const eunomia_ebpf_program::format_info &f)
  {
    printf(f.print_fmt, *(T *)(data + f.field_offset / 8));
    printf(" ");
  }

  static const std::map<std::size_t, std::function<void(const char *data, const eunomia_ebpf_program::format_info &f)>>
      print_func_lookup_map = {
        { 1, print_rb_field<uint8_t> },
        { 2, print_rb_field<uint16_t> },
        { 4, print_rb_field<uint32_t> },
        { 8, print_rb_field<uint64_t> },
      };

  /// FIXME: output config with lua
  void eunomia_ebpf_program::print_event_with_default_types(const char *event) const
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

  int handle_print_ringbuf_event(void *ctx, void *data, size_t data_sz)
  {
    const char *e = (const char *)(const void *)data;
    const eunomia_ebpf_program *p = (const eunomia_ebpf_program *)ctx;
    if (!p && !e) {
      std::cerr << "empty ctx or events" << std::endl;
      return -1;
    }
    p->print_event_with_default_types(e);
    return 0;
  }

}  // namespace eunomia
