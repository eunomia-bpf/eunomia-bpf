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

  static void from_json(const nlohmann::json &j, ebpf_rb_export_field_meta_data &data)
  {
    j.at("Name").get_to(data.name);
    j.at("Type").get_to(data.type);
    j.at("FieldOffset").get_to(data.field_offset);
    j.at("LLVMType").get_to(data.llvm_type);
  }

  static void from_json(const nlohmann::json &j, ebpf_export_types_meta_data &data)
  {
    j.at("Alignment").get_to(data.alignment);
    j.at("DataSize").get_to(data.data_size);
    j.at("Size").get_to(data.size);
    j.at("Struct Name").get_to(data.struct_name);
    j.at("Fields").get_to(data.fields);
  }

  void ebpf_export_types_meta_data::from_json_str(const std::string &j_str)
  {
    json j = json::parse(j_str);
    ebpf_export_types_meta_data meta = j.get<ebpf_export_types_meta_data>();
    *this = meta;
    return;
  }

  static void from_json(const nlohmann::json &j, ebpf_progs_meta_data &data)
  {
    get_from_json_at(name);
    get_opt_from_json_at(type);
  }

  static void from_json(const nlohmann::json &j, ebpf_btf_type_meta_data &data)
  {
    get_from_json_at(name);
    get_from_json_at(type);
    get_from_json_at(size);
  }

  static void from_json(const nlohmann::json &j, ebpf_maps_meta_data &data)
  {
    get_from_json_at(name);
    get_from_json_at(type);
    get_opt_from_json_at(export_data_types);
    get_opt_from_json_at(sec_data);
  }

  bool ebpf_maps_meta_data::is_rodata(void) const
  {
    return str_ends_with(name, ".rodata");
  }
  bool ebpf_maps_meta_data::is_bss(void) const
  {
    return str_ends_with(name, ".bss");
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

  int eunomia_ebpf_program::load_json_config(const std::string &json_str) noexcept
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
  eunomia_ebpf_program::eunomia_ebpf_program(const std::string &json_str)
  {
    int res = load_json_config(json_str);
    if (res != 0)
    {
      std::cerr << "failed to load json config" << std::endl;
    }
  }
}  // namespace eunomia
