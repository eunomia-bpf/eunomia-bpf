#include <iostream>
#include <thread>

#include "base64.h"
#include "eunomia/eunomia-bpf.hpp"
#include "json.hpp"
#include "zlib.h"

extern "C" {
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
}

using json = nlohmann::json;
namespace eunomia {
/// use as a optional field
/// if the field exists, we get it.
#define get_opt_from_json_at(name) \
    do {                           \
        json res;                  \
        try {                      \
            res = j.at(#name);     \
        } catch (...) {            \
            break;                 \
        }                          \
        res.get_to(data.name);     \
    } while (0);

/// get from json
/// throw an error if get failed.
#define get_from_json_at(name)         \
    {                                  \
        j.at(#name).get_to(data.name); \
    }

static void
from_json(const nlohmann::json &j, export_types_struct_member_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(type);
    get_from_json_at(size);
    get_from_json_at(bit_offset);
    get_opt_from_json_at(bit_size);
    get_opt_from_json_at(type_id);
}

static void
from_json(const nlohmann::json &j, export_types_struct_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(size);
    get_from_json_at(type_id);
    get_from_json_at(members);
}

static void
from_json(const nlohmann::json &j, prog_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(attach);
    get_from_json_at(link);

    data.__raw_json_data = j.dump();
}

static void
from_json(const nlohmann::json &j, map_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(ident);
    get_opt_from_json_at(mmaped);

    data.__raw_json_data = j.dump();
}

static void
from_json(const nlohmann::json &j, data_section_variable_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(type);
    get_from_json_at(size);
    get_from_json_at(offset);
    get_from_json_at(type_id);

    data.__raw_json_data = j.dump();
}

static void
from_json(const nlohmann::json &j, data_section_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(variables);
}

static void
from_json(const nlohmann::json &j, bpf_skel_meta &data)
{
    get_from_json_at(obj_name);
    get_from_json_at(maps);
    get_from_json_at(progs);
    get_from_json_at(data_sections);
}

static void
from_json(const nlohmann::json &j, eunomia_object_meta &data)
{
    get_opt_from_json_at(export_types);
    get_from_json_at(bpf_skel);
    get_opt_from_json_at(perf_buffer_pages);
    get_opt_from_json_at(perf_buffer_time_ms);
    get_opt_from_json_at(poll_timeout_ms);
    get_opt_from_json_at(print_header);
}

void
eunomia_object_meta::from_json_str(const std::string &j_str)
{
    json jj = json::parse(j_str);
    from_json(jj, *this);
}

int
bpf_skeleton::open_from_json_config(
    const std::string &json_str, std::vector<char> bpf_object_buffer) noexcept
{
    try {
        state = ebpf_program_state::INIT;
        meta_data.from_json_str(json_str);
        __bpf_object_buffer = bpf_object_buffer;
        return 0;
    } catch (...) {
        std::cerr << "failed to parse json" << std::endl;
        state = ebpf_program_state::INVALID;
        return -1;
    }
}

int
bpf_skeleton::open_from_json_config(const std::string &json_package) noexcept
{
    std::vector<char> bpf_object_buffer;
    std::string json_str;
    try {
        json j = json::parse(json_package);
        std::string base64_bpf_object = j.at("bpf_object");
        std::size_t bpf_object_size = j.at("bpf_object_size");
        json_str = j.at("meta").dump();
        std::vector<unsigned char> compress_obj =
            base64_decode((const unsigned char *)base64_bpf_object.data(),
                          base64_bpf_object.size());
        bpf_object_buffer.resize(bpf_object_size + 256);
        unsigned long size = bpf_object_size + 256;
        int res = uncompress((Bytef *)bpf_object_buffer.data(), &size,
                             (Bytef *)compress_obj.data(), compress_obj.size());
        if (res != Z_OK) {
            std::cerr << "failed to uncompress bpf object: " << res << " size "
                      << size << " bpf_object_size: " << bpf_object_size << " "
                      << compress_obj.size() << std::endl;
            return -1;
        }
    } catch (...) {
        std::cerr << "failed to parse json" << std::endl;
        state = ebpf_program_state::INVALID;
        return -1;
    }
    return open_from_json_config(json_str, bpf_object_buffer);
}

/// create a ebpf program from json str
bpf_skeleton::bpf_skeleton(const std::string &json_str,
                           std::vector<char> bpf_object_buffer)
{
    int res = open_from_json_config(json_str, std::move(bpf_object_buffer));
    if (res != 0) {
        std::cerr << "failed to load json config" << std::endl;
    }
}
} // namespace eunomia
