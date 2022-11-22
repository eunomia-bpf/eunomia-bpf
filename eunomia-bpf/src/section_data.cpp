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
    T value = json_obj["value"];
    memcpy(buffer + offset, &value, size);
}

void
load_string_data(const json &json_obj, char *buffer, size_t offset, size_t size)
{
    std::string value = json_obj["value"];
    memcpy(buffer + offset, &value, size);
}

struct section_data_btf_type {
    uint32_t id;
    uint32_t size;
    uint32_t offset;
    bool is_array;
};

static std::map<std::string, section_data_btf_type>
resolve_btf_section_types(const data_section_meta &sec_meta, const btf *btf)
{
    std::map<std::string, section_data_btf_type> btf_type_map;

    int id = btf__find_by_name(btf, sec_meta.name.c_str());
    if (id < 0) {
        std::cerr << "failed to find btf type for section " << sec_meta.name
                  << std::endl;
        return {};
    }
    auto sec = btf__type_by_id(btf, (unsigned int)id);
    if (!sec) {
        return {};
    }
    const struct btf_var_secinfo *sec_var = btf_var_secinfos(sec);
    int i, err, vlen = btf_vlen(sec);
    unsigned int off = 0;

    for (i = 0; i < vlen; i++, sec_var++) {
        const struct btf_type *var = btf__type_by_id(btf, sec_var->type);
        const char *var_name = btf__name_by_offset(btf, var->name_off);
        unsigned int need_off = sec_var->offset, align_off, align;
        __u32 var_type_id = var->type;

        if (off > need_off) {
            fprintf(stderr,
                    "Something is wrong for %s's variable #%d: need offset %d, "
                    "already at %d.\n",
                    sec_meta.name.c_str(), i, need_off, off);
            return {};
        }
        btf_type_map[var_name] = { var_type_id, sec_var->size, sec_var->offset,
                                   btf_is_array(var) };
        off = sec_var->offset + sec_var->size;
    }
    return btf_type_map;
}

void
bpf_skeleton::load_section_data_to_buffer(const data_section_meta &sec_meta,
                                          char *mmap_buffer)
{
    auto btf = get_btf_data();
    if (!btf) {
        std::cerr << "error: btf is null" << std::endl;
        return;
    }
    auto btf_type_map = resolve_btf_section_types(sec_meta, btf);
    if (btf_type_map.empty()) {
        return;
    }

    for (auto &variable : sec_meta.variables) {
        if (btf_type_map.find(variable.name) == btf_type_map.end()) {
            std::cerr << "error: variable not found: " << variable.name
                      << std::endl;
            continue;
        }
        auto &sec_btf_type = btf_type_map[variable.name];
        json json_obj = json::parse(variable.__raw_json_data);
        if (!json_obj.contains("value")) {
            return;
        }
        if (config_data.libbpf_debug_verbose) {
            std::cerr << "load runtime arg: " << json_obj["value"] << std::endl;
        }
        if (sec_btf_type.is_array) {
            if (strncmp(variable.type.c_str(), "char", 4) == 0) {
                load_string_data(json_obj, mmap_buffer, sec_btf_type.offset,
                                 sec_btf_type.size);
            }
        }
        switch (sec_btf_type.size) {
            case 1:
                load_data<std::uint8_t>(json_obj, mmap_buffer,
                                        sec_btf_type.offset, sec_btf_type.size);
                break;
            case 2:
                load_data<std::uint16_t>(json_obj, mmap_buffer,
                                         sec_btf_type.offset,
                                         sec_btf_type.size);
                break;
            case 4:
                load_data<std::uint32_t>(json_obj, mmap_buffer,
                                         sec_btf_type.offset,
                                         sec_btf_type.size);
                break;
            case 8:
                load_data<std::uint64_t>(json_obj, mmap_buffer,
                                         sec_btf_type.offset,
                                         sec_btf_type.size);
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