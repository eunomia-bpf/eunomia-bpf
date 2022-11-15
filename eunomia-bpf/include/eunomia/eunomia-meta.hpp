#ifndef EUNOMIA_MATA_DATA_
#define EUNOMIA_MATA_DATA_

#include <string>
#include <vector>

namespace eunomia
{

  struct export_types_member_meta_data
  {
    std::string name;
    std::string type;
    std::string llvm_type;
    uint32_t field_offset;
  };

  struct ebpf_export_types_meta_data
  {
    std::vector<export_types_member_meta_data> fields;
    std::string struct_name;
    uint32_t size;
    uint32_t data_size;
    uint32_t alignment;
    void from_json_str(const std::string &j_str);
  };

  struct ebpf_btf_type_meta_data
  {
    std::string name;
    std::string type;
    std::size_t size;
  };

  struct ebpf_maps_meta_data
  {
    std::string name;
    std::string type;
    ebpf_export_types_meta_data export_data_types;
    std::vector<ebpf_btf_type_meta_data> sec_data;

    bool is_rodata(void) const;
    bool is_bss(void) const;
  };


  struct ebpf_progs_meta_data
  {
    std::string name;
    std::string type;
  };

  /// meta data
  struct bpf_skel_meta_data
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