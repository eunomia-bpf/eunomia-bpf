#ifndef EUNOMIA_PROCESSOR_HPP
#define EUNOMIA_PROCESSOR_HPP

#include "eunomia-config.hpp"
#include "eunomia-meta.hpp"

namespace eunomia
{
  class bpf_skeleton;

  class data_section_processor
  {
   protected:
    /// @brief preserve the meta data json for further use
    std::string runtime_args;
    void load_section_data(std::size_t index, const ebpf_maps_meta_data& map, char* buffer);

   public:
    eunomia_ebpf_meta_data create_meta_from_json(const std::string& json_str);
    void load_map_data(bpf_skeleton& prog);
   ~data_section_processor() = default;
  };
}  // namespace eunomia

#endif
