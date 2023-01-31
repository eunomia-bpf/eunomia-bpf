/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */

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
/// if the field exists, get it. if not, use the default value
#define get_from_json_at_or_default(name) \
    do {                                  \
        json res;                         \
        try {                             \
            res = j.at(#name);            \
        } catch (...) {                   \
            break;                        \
        }                                 \
        res.get_to(data.name);            \
    } while (0);

/// if the field exists, get it to std::optional.
#define get_from_json_at_optional(name)     \
    do {                                    \
        json res;                           \
        try {                               \
            if (j.find(#name) != j.end()) { \
                data.name = j.at(#name);    \
            }                               \
        } catch (...) {                     \
            break;                          \
        }                                   \
    } while (0);

/// get from json
/// throw an error if get failed.
#define get_from_json_at(name)                                             \
    do {                                                                   \
        json res;                                                          \
        try {                                                              \
            res = j.at(#name);                                             \
        } catch (...) {                                                    \
            std::cerr << "error: get " << #name << " failed" << std::endl; \
            throw std::runtime_error("json parse error: " #name);          \
            break;                                                         \
        }                                                                  \
        res.get_to(data.name);                                             \
    } while (0);

static void
from_json(const nlohmann::json &j, export_types_struct_member_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(type);
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
from_json(const nlohmann::json &j, map_sample_meta &data)
{
    get_from_json_at(interval);
    get_from_json_at_or_default(type);
    get_from_json_at_or_default(unit);
    get_from_json_at_or_default(clear_map);
}

static void
from_json(const nlohmann::json &j, map_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(ident);
    get_from_json_at_or_default(mmaped);
    get_from_json_at_optional(sample);

    data.__raw_json_data = j.dump();
}

static void
from_json(const nlohmann::json &j, data_section_variable_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(type);

    data.__raw_json_data = j.dump();
}

static void
from_json(const nlohmann::json &j, data_section_meta &data)
{
    get_from_json_at(name);
    get_from_json_at(variables);
}

static void
from_json(const nlohmann::json &j, bpf_skel_doc &data)
{
    get_from_json_at_or_default(version);
    get_from_json_at_or_default(brief);
    get_from_json_at_or_default(details);
}

static void
from_json(const nlohmann::json &j, bpf_skel_meta &data)
{
    get_from_json_at(obj_name);
    get_from_json_at(maps);
    get_from_json_at(progs);
    get_from_json_at(data_sections);
    get_from_json_at_optional(doc);
}

static void
from_json(const nlohmann::json &j, eunomia_object_meta &data)
{
    get_from_json_at_or_default(export_types);
    get_from_json_at(bpf_skel);
    get_from_json_at_or_default(perf_buffer_pages);
    get_from_json_at_or_default(perf_buffer_time_ms);
    get_from_json_at_or_default(poll_timeout_ms);
    get_from_json_at_or_default(debug_verbose);
    get_from_json_at_or_default(print_header);
}

void
bpf_skel_meta::from_json_str(const std::string &j_str)
{
    json j = json::parse(j_str);
    j.get_to(*this);
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
    } catch (std::runtime_error &e) {
        std::cerr << "failed to parse json " << e.what() << std::endl;
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
    } catch (std::runtime_error &e) {
        std::cerr << "failed to parse json " << e.what() << std::endl;
        state = ebpf_program_state::INVALID;
        return -1;
    }
    return open_from_json_config(json_str, bpf_object_buffer);
}
} // namespace eunomia
