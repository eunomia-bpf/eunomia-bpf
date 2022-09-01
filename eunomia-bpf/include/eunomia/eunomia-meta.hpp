#ifndef EUNOMIA_MATA_DATA_
#define EUNOMIA_MATA_DATA_

#include <string>
#include <vector>

namespace eunomia
{

  struct ebpf_rb_export_field_meta_data
  {
    std::string name;
    std::string type;
    std::string llvm_type;
    uint32_t field_offset;
  };

  struct ebpf_export_types_meta_data
  {
    std::vector<ebpf_rb_export_field_meta_data> fields;
    std::string struct_name;
    uint32_t size;
    uint32_t data_size;
    uint32_t alignment;
    void from_json_str(const std::string &j_str);
  };

  struct ebpf_maps_meta_data
  {
    std::string name;
    std::string type;
    ebpf_export_types_meta_data export_data_types;
  };

  struct ebpf_progs_meta_data
  {
    std::string name;
    std::string type;
  };

  /// meta data
  struct eunomia_ebpf_meta_data
  {
    // ebpf name
    std::string ebpf_name;
    std::vector<ebpf_maps_meta_data> maps;
    std::vector<ebpf_progs_meta_data> progs;
    size_t data_sz;
    std::string ebpf_data;

    std::string to_json_str();
    void from_json_str(const std::string &j_str);
  };

}  // namespace eunomia

#endif