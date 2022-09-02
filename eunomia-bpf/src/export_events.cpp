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
  struct print_type_format_map
  {
    const char *format;
    const char *type_str;
    const char *llvm_type_str;
  };

  static const print_type_format_map base_type_look_up_table[] = {
    { "%llx", "unsigned __int128", "i128" },
    { "%llu", "unsigned long long", "i64" },
    { "%lld", "long long", "i64" },
    { "%d", "int", "i32" },
    { "%u", "unsigned int", "i32" },
    { "%hu", "unsigned short", "i16" },
    { "%hd", "short", "i16" },
    { "%d", "unsigned char", "i8" },
    { "%c", "char", "i8" },
    { "%c", "_Bool", "i8" },
    // Support more types?
  };

  void eunomia_event_exporter::add_export_type_with_fmt(export_type_info f)
  {
    auto info = f;
    switch (format_type)
    {
      case export_format_type::EEXPORT_JSON:
      {
        if (info.llvm_type == "cstring")
        {
          // print as json type string
          info.print_fmt = std::string("\"") + info.name + "\":\"" + info.print_fmt + "\"";
        }
        else
        {
          // print as json type integer
          info.print_fmt = std::string("\"") + info.name + "\":" + info.print_fmt;
        }
      }
      break;
      default: break;
    }
    checked_export_types.emplace_back(info);
  }

  void eunomia_event_exporter::check_and_add_export_type(ebpf_rb_export_field_meta_data &field, std::size_t width)
  {
    bool is_vaild_type = false;
    // use the lookup table to determine format
    for (auto &type : base_type_look_up_table)
    {
      // match basic types first, if not match, try llvm types
      if (field.type == type.type_str || field.llvm_type == type.llvm_type_str)
      {
        add_export_type_with_fmt({ type.format, field.field_offset, width, field.name, field.llvm_type });
        is_vaild_type = true;
        break;
      }
      else if (field.llvm_type.size() > 0)
      {
        // a simple and naive match for arrays
        if (field.llvm_type.front() == '[' && field.type.size() > 4 && std::strncmp(field.type.c_str(), "char", 4) == 0)
        {
          // maybe a char array: fix this
          add_export_type_with_fmt({ "%s", field.field_offset, width, field.name, "cstring" });
          is_vaild_type = true;
          break;
        }
      }
    }
    if (!is_vaild_type)
    {
      std::cerr << "Unsupported type: " << field.type << " " << field.llvm_type << std::endl;
    }
  }

  void eunomia_event_exporter::print_export_types_header(void)
  {
    // print the time header
    std::cout << "time ";
    for (auto &type : checked_export_types)
    {
      std::cout << type.name << ' ';
    }
    // print the field name endline
    std::cout << std::endl;
  }

  int eunomia_event_exporter::check_for_meta_types_and_create_export_format(ebpf_export_types_meta_data &types)
  {
    auto fields = types.fields;
    // clean the last fields
    checked_export_types.clear();
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
        width = types.data_size - field.field_offset;
      }
      // use the byte number instead of the width
      width /= 8;
      check_and_add_export_type(field, width);
    }
    if (checked_export_types.size() == 0)
    {
      std::cerr << "No available format type!" << std::endl;
      return -1;
    }
    else if (user_export_event_handler == nullptr && format_type == export_format_type::EEXPORT_PLANT_TEXT)
    {
      print_export_types_header();
    }
    return 0;
  }

  struct sprintf_printer
  {
    char *output_buffer_pointer = nullptr;
    std::size_t output_buffer_left = 0;
    char *buffer_base = nullptr;
    sprintf_printer(std::vector<char> &buffer, std::size_t max_size)
    {
      buffer.resize(max_size, 0);
      output_buffer_pointer = buffer.data();
      output_buffer_left = buffer.size();
      buffer_base = buffer.data();
    }
    int update_buffer(int res)
    {
      if (res < 0)
      {
        std::cerr << "Failed to sprint event" << std::endl;
        return res;
      }
      output_buffer_pointer += res;
      output_buffer_left -= static_cast<std::size_t>(res);
      if (output_buffer_left <= 1)
      {
        std::cerr << "Failed to sprint event, buffer size limited" << std::endl;
        return -1;
      }
      return res;
    }
    int snprintf_event(const char *fmt, ...)
    {
      va_list args;
      va_start(args, fmt);
      int res = vsnprintf(output_buffer_pointer, output_buffer_left, fmt, args);
      va_end(args);
      return update_buffer(res);
    }
    void export_to_handler_or_print(export_event_handler &user_export_event_handler)
    {
      *output_buffer_pointer = 0;
      if (user_export_event_handler != nullptr)
      {
        user_export_event_handler(buffer_base);
      }
      else
      {
        printf("%s\n", buffer_base);
      }
    }
  };

  template<typename T>
  static int print_export_field(const char *data, const export_type_info &f, sprintf_printer &recorder)
  {
    auto *field = reinterpret_cast<const T *>(data + f.field_offset / 8);
    return std::snprintf(recorder.output_buffer_pointer, recorder.output_buffer_left, f.print_fmt.c_str(), *field);
  }

  static int print_export_cstring(const char *data, const export_type_info &f, sprintf_printer &recorder)
  {
    auto *field = reinterpret_cast<const char *>(data + f.field_offset / 8);
    return std::snprintf(recorder.output_buffer_pointer, recorder.output_buffer_left, f.print_fmt.c_str(), field);
  }

  static const std::
      map<std::string, std::function<int(const char *data, const export_type_info &f, sprintf_printer &recorder)>>
          print_func_lookup_map = { { "i8", print_export_field<uint8_t> },       { "i16", print_export_field<uint16_t> },
                                    { "i32", print_export_field<uint32_t> },     { "i64", print_export_field<uint64_t> },
                                    { "i128", print_export_field<__uint128_t> }, { "cstring", print_export_cstring } };

  void eunomia_event_exporter::print_export_event_to_json(const char *event)
  {
    sprintf_printer printer{ export_event_buffer, EXPORT_BUFFER_SIZE };

    int res = printer.snprintf_event("{");
    if (res < 0)
    {
      return;
    }
    for (std::size_t i = 0; i < checked_export_types.size(); ++i)
    {
      auto &f = checked_export_types[i];
      auto func = print_func_lookup_map.find(f.llvm_type);
      if (func != print_func_lookup_map.end())
      {
        res = printer.update_buffer(func->second((const char *)event, f, printer));
        if (res < 0)
        {
          return;
        }
      }
      if (i < checked_export_types.size() - 1)
      {
        res = printer.snprintf_event(",");
        if (res < 0)
        {
          return;
        }
      }
    }
    res = printer.snprintf_event("}");
    if (res < 0)
    {
      return;
    }
    printer.export_to_handler_or_print(user_export_event_handler);
  }

  void eunomia_event_exporter::print_plant_text_event_with_time(const char *event)
  {
    struct tm *tm;
    char ts[32];
    time_t t;
    sprintf_printer printer{ export_event_buffer, EXPORT_BUFFER_SIZE };

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    int res = printer.snprintf_event("%-8s ", ts);
    if (res < 0)
    {
      return;
    }

    for (const auto &f : checked_export_types)
    {
      auto func = print_func_lookup_map.find(f.llvm_type);
      if (func != print_func_lookup_map.end())
      {
        res = printer.update_buffer(func->second((const char *)event, f, printer));
        if (res < 0)
        {
          return;
        }
        res = printer.snprintf_event(" ");
        if (res < 0)
        {
          return;
        }
      }
    }
    res = printer.snprintf_event("\n");
    if (res < 0)
    {
      return;
    }
    printer.export_to_handler_or_print(user_export_event_handler);
  }

  /// FIXME: output config with lua
  void eunomia_event_exporter::handler_export_events(const char *event) const
  {
    if (!event)
    {
      return;
    }
    if (internal_event_processor)
    {
      internal_event_processor(event);
      return;
    }
    else
    {
      assert(false && "No export event handler!");
    }
  }

  void eunomia_event_exporter::set_export_type(export_format_type type, export_event_handler handler)
  {
    format_type = type;
    /// preserve the user defined handler
    user_export_event_handler = handler;
    switch (format_type)
    {
      case export_format_type::EEXPORT_JSON:
      {
        internal_event_processor =
            std::bind(&eunomia_event_exporter::print_export_event_to_json, this, std::placeholders::_1);
      }
      break;
      case export_format_type::EEXPORT_RAW_EVENT: internal_event_processor = handler; break;
      case export_format_type::EEXPORT_PLANT_TEXT: [[fallthrough]];
      default:
        internal_event_processor =
            std::bind(&eunomia_event_exporter::print_plant_text_event_with_time, this, std::placeholders::_1);
        break;
    }
  }

  void eunomia_ebpf_program::handler_export_events(const char *event) const
  {
    event_exporter.handler_export_events(event);
  }

  int eunomia_ebpf_program::wait_and_export_to_handler(enum export_format_type type, export_event_handler handler) noexcept
  {
    event_exporter.set_export_type(type, handler);
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

}  // namespace eunomia
