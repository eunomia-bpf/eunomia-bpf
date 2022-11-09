#ifndef EUNOMIA_MATA_DATA_
#define EUNOMIA_MATA_DATA_

#include <string>
#include <vector>

namespace eunomia {

struct export_types_struct_member_meta {
    std::string name;
    std::string type;
    uint32_t size;
    uint32_t bit_offset;
    uint32_t bit_size;
};

struct export_types_struct_meta {
    std::vector<export_types_struct_member_meta> members;
    std::string name;
    uint32_t size;
    uint32_t type_id;
    void from_json_str(const std::string &j_str);
};

struct map_meta {
    std::string name;
    std::string ident;
    bool mmaped;

    bool is_rodata(void) const;
    bool is_bss(void) const;
};

struct prog_meta {
    std::string name;
    std::string attach;
    bool link;
};

struct data_section_variable_meta {
    std::string name;
    std::string type;
    uint32_t size;
    uint32_t offset;
    uint32_t type_id;
};

struct data_section_meta {
    std::string name;
    std::vector<data_section_variable_meta> variables;
};

struct bpf_skel_meta {
    std::vector<data_section_meta> data_sections;
    std::vector<map_meta> maps;
    std::vector<prog_meta> progs;
    std::string obj_name;
};

/// meta data
struct eunomia_object_meta {
    bpf_skel_meta bpf_skel;
    std::vector<export_types_struct_meta> export_types;

    std::string to_json_str();
    void from_json_str(const std::string &j_str);
};

} // namespace eunomia

#endif