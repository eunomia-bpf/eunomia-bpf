#include "eunomia/eunomia-bpf.hpp"
#include "json.hpp"

using nlohmann::json;

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/btf.h>
}

namespace eunomia {

template<typename T>
void
load_data(const json &json_obj, char *buffer, size_t offset, size_t size)
{
    if (!json_obj.contains("value")) {
        return;
    }
    T value = json_obj["value"];
    std::cout << "load runtime arg: " << value << std::endl;
    memcpy(buffer + offset, &value, size);
}

void
load_string_data(const json &json_obj, char *buffer, size_t offset, size_t size)
{
    if (!json_obj.contains("value")) {
        return;
    }
    std::string value = json_obj["value"];
    std::cout << "load string arg: " << value << std::endl;
    memcpy(buffer + offset, &value, size);
}

void
bpf_skeleton::load_section_data_to_buffer(const data_section_meta &sec,
                                          char *mmap_buffer)
{
    auto btf = get_btf_data();

    for (auto &variable : sec.variables) {
        auto btf_type = btf__type_by_id(btf, variable.type_id);
        if (btf_is_array(btf_type)) {
            if (strncmp(variable.type.c_str(), "char", 4) == 0) {
                load_string_data(variable.__raw_json_data, mmap_buffer,
                                 variable.offset, variable.size);
            }
        }
        switch (variable.size) {
            case 1:
                load_data<std::uint8_t>(variable.__raw_json_data, mmap_buffer,
                                        variable.offset, variable.size);
                break;
            case 2:
                load_data<std::uint16_t>(variable.__raw_json_data, mmap_buffer,
                                         variable.offset, variable.size);
                break;
            case 4:
                load_data<std::uint32_t>(variable.__raw_json_data, mmap_buffer,
                                         variable.offset, variable.size);
                break;
            case 8:
                load_data<std::uint64_t>(variable.__raw_json_data, mmap_buffer,
                                         variable.offset, variable.size);
                break;
        }
    }
}

void
bpf_skeleton::load_section_data()
{
    for (auto &sec : meta_data.bpf_skel.data_sections) {
        if (sec.name == ".rodata") {
            load_section_data_to_buffer(sec, rodata_buffer);
        }
        else if (sec.name == ".bss") {
            load_section_data_to_buffer(sec, bss_buffer);
        }
        else {
            std::cerr << "unsupported section: " << sec.name << std::endl;
        }
    }
}
} // namespace eunomia