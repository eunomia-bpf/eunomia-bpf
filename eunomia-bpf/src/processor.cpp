#include "eunomia/processor.hpp"

#include "eunomia/eunomia-bpf.hpp"
#include "json.hpp"

using nlohmann::json;

namespace eunomia
{
  bpf_skel_meta_data data_section_processor::create_meta_from_json(const std::string& json_str)
  {
    bpf_skel_meta_data meta_data;
    meta_data.from_json_str(json_str);
    try
    {
      auto json_obj = json::parse(json_str);
      this->runtime_args = json_obj["runtime_args"].dump();
    }
    catch (...)
    {
    }
    return meta_data;
  }

  template<typename T>
  void load_data(const json& json_obj, const std::string& name, char* buffer, size_t offset)
  {
    if (!json_obj.contains(name))
    {
      return;
    }
    T value = json_obj[name];
    std::cout << "load runtime arg: " << name << " " << value << std::endl;
    memcpy(buffer + offset, &value, sizeof(T));
  }

  void data_section_processor::load_section_data(std::size_t index, const ebpf_maps_meta_data& map, char* buffer)
  {
    if (!buffer || runtime_args.empty())
    {
      return;
    }
    json json_obj;
    try
    {
      json_obj = json::parse(runtime_args);
    }
    catch (...)
    {
      return;
    }
    std::size_t offset = 0;
    for (auto& sec : map.sec_data)
    {
      switch (sec.size)
      {
        case 1: load_data<std::uint8_t>(json_obj, sec.name, buffer, offset); break;
        case 2: load_data<std::uint16_t>(json_obj, sec.name, buffer, offset); break;
        case 4: load_data<std::uint32_t>(json_obj, sec.name, buffer, offset); break;
        case 8: load_data<std::uint64_t>(json_obj, sec.name, buffer, offset); break;
        default:
          // string or other type
          if (std::strncmp(sec.type.c_str(), "char[", 5) == 0)
          {
            std::string len_str = sec.type.substr(5, sec.type.size() - 6);
            std::size_t len = std::stoul(len_str);
            auto obj = json_obj[sec.name];
            if (obj.is_null())
            {
              break;
            }
            std::string value = obj;
            std::cout << "load runtime arg: " << sec.name << " " << value << std::endl;
            memcpy(buffer + offset, value.c_str(), value.size() > len ? len : value.size());
            offset += len;
            continue;
          }
          else
          {
            std::cerr << "unsupported type: " << sec.type << std::endl;
          }
      }
      offset += sec.size;
    }
  }

  void data_section_processor::load_map_data(bpf_skeleton& prog)
  {
    if (runtime_args.length() == 0)
    {
      return;
    }
    for (size_t i = 0; i < prog.meta_data.maps.size(); i++)
    {
      auto& map = prog.meta_data.maps[i];
      if (map.is_rodata())
      {
        load_section_data(i, map, prog.rodata_buffer);
      }
      else if (map.is_bss())
      {
        load_section_data(i, map, prog.rodata_buffer);
      }
    }
  }
}  // namespace eunomia