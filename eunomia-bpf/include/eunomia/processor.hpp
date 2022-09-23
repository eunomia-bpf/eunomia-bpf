#ifndef EUNOMIA_PROCESSOR_HPP
#define EUNOMIA_PROCESSOR_HPP

#include "eunomia-config.hpp"
#include "eunomia-meta.hpp"

namespace eunomia
{
  class eunomia_ebpf_program;
  /// @brief   process the data in eBPF program
  /// @details base on the config data, dynamic load config
  /// into the eBPF maps and sections, for example:
  /// - set the global variable in ro-data section
  /// - reorder the data before run eBPF program
  class eunomia_processor
  {
   public:
    /// @brief create program meta data from json
    /// @param json_str config json str
    /// @return meta data
    virtual eunomia_ebpf_meta_data create_meta_from_json(const std::string& json_str) = 0;
    /// @brief load the data of maps and secs
    /// @param prog the program after the eBPF skeleton has been opened
    virtual void load_map_data(eunomia_ebpf_program& prog) = 0;
    virtual ~eunomia_processor() = default;
  };

  class eunomia_raw_processor : public eunomia_processor
  {
   private:
    /// @brief preserve the meta data json for further use
    std::string runtime_args;
    void load_section_data(std::size_t index, const ebpf_maps_meta_data& map, char* buffer);

   public:
    eunomia_ebpf_meta_data create_meta_from_json(const std::string& json_str) override;
    void load_map_data(eunomia_ebpf_program& prog) override;
    virtual ~eunomia_raw_processor() = default;
  };
}  // namespace eunomia

#endif
