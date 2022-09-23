#include "eunomia/processor.hpp"

namespace eunomia
{
  eunomia_ebpf_meta_data eunomia_raw_processor::create_meta_from_json(const std::string& json_str)
  {
    eunomia_ebpf_meta_data meta_data;
    meta_data.from_json_str(json_str);
    return meta_data;
  }
  void eunomia_raw_processor::load_map_data(eunomia_ebpf_program& prog)
  {
  }
}  // namespace eunomia