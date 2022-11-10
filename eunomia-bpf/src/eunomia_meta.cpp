#include <iostream>
#include <thread>

#include "base64.h"
#include "eunomia/eunomia-bpf.hpp"
#include "eunomia/utils.hpp"
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

  static void from_json(const nlohmann::json &j, export_types_struct_member_meta &data)
  {
    get_from_json_at(name);
    get_from_json_at(type);
    get_from_json_at(size);
    get_from_json_at(bit_offset);
    get_opt_from_json_at(bit_size);
    get_opt_from_json_at(type_id);
  }

  static void from_json(const nlohmann::json &j, export_types_struct_meta &data)
  {
    get_from_json_at(name);
    get_from_json_at(size);
    get_from_json_at(type_id);
    get_from_json_at(members);
  }

  static void from_json(const nlohmann::json &j, prog_meta &data)
  {
    get_from_json_at(name);
    get_from_json_at(attach);
    get_from_json_at(link);
  }

  static void from_json(const nlohmann::json &j, map_meta &data)
  {
    get_from_json_at(name);
    get_from_json_at(ident);
    get_opt_from_json_at(mmaped);
  }

  bool map_meta::is_rodata(void) const
  {
    return str_ends_with(name, ".rodata");
  }
  bool map_meta::is_bss(void) const
  {
    return str_ends_with(name, ".bss");
  }

  static void from_json(const nlohmann::json &j, data_section_variable_meta &data)
  {
    get_from_json_at(name);
    get_from_json_at(type);
    get_from_json_at(size);
    get_from_json_at(offset);
    get_from_json_at(type_id);
  }

  static void from_json(const nlohmann::json &j, data_section_meta &data)
  {
    get_from_json_at(name);
    get_from_json_at(variables);
  }

  static void from_json(const nlohmann::json &j, bpf_skel_meta &data)
  {
    get_from_json_at(obj_name);
    get_from_json_at(maps);
    get_from_json_at(progs);
    get_from_json_at(data_sections);
  }

  static void from_json(const nlohmann::json &j, eunomia_object_meta &data)
  {
    get_opt_from_json_at(export_types);
    get_from_json_at(bpf_skel);
    get_opt_from_json_at(perf_buffer_pages);
    get_opt_from_json_at(perf_buffer_time_ms);
    get_opt_from_json_at(poll_timeout_ms);
    get_opt_from_json_at(print_header);
  }

  void eunomia_object_meta::from_json_str(const std::string &j_str)
  {
    json jj = json::parse(j_str);
    from_json(jj, *this); 
  }

  int bpf_skeleton::open_from_json_config(const std::string &json_str, std::vector<char> bpf_object_buffer) noexcept
  {
    try
    {
      meta_data = processor.create_meta_from_json(json_str);
      state = ebpf_program_state::INIT;
      return 0;
    }
    catch (...)
    {
      std::cerr << "failed to parse json" << std::endl;
      state = ebpf_program_state::INVALID;
      return -1;
    }
  }

  /// create a ebpf program from json str
  bpf_skeleton::bpf_skeleton(const std::string &json_str, std::vector<char> bpf_object_buffer)
  {
    int res = open_from_json_config(json_str, std::move(bpf_object_buffer));
    if (res != 0)
    {
      std::cerr << "failed to load json config" << std::endl;
    }
  }
}  // namespace eunomia
