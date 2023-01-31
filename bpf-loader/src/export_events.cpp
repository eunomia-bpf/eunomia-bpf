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
#include <optional>

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include "helpers/trace_helpers.h"
}

namespace eunomia {
struct print_type_format_map {
    const char *format;
    const char *type_str;
};

static bool
is_string_type(const char *type_str)
{
    return strncmp(type_str, "char[", 5) == 0;
}

static bool
is_bool_type(const char *type_str)
{
    return strncmp(type_str, "bool", 4) == 0;
}

static void
btf_dump_event_printf(void *ctx, const char *fmt, va_list args)
{
    auto printer = static_cast<event_exporter::sprintf_printer *>(ctx);
    printer->vsprintf_event(fmt, args);
}

static const char *
btf_str(const struct btf *btf, __u32 off)
{
    if (!off)
        return "(anon)";
    return btf__name_by_offset(btf, off) ?: "(invalid)";
}

int
event_exporter::check_export_types_btf(export_types_struct_meta &struct_meta)
{
    auto t = btf__type_by_id(exported_btf, struct_meta.type_id);
    if (!t || !btf_is_struct(t)) {
        std::cerr << "type id " << struct_meta.type_id << " is not struct"
                  << std::endl;
    }
    if (struct_meta.name != btf__name_by_offset(exported_btf, t->name_off)) {
        std::cerr << "type name " << struct_meta.name << " is not matched "
                  << btf__name_by_offset(exported_btf, t->name_off)
                  << std::endl;
    }
    btf_member *m = btf_members(t);
    __u16 vlen = BTF_INFO_VLEN(t->info);
    for (size_t i = 0; i < vlen; i++, m++) {
        auto member = struct_meta.members[i];
        if (member.name != btf__name_by_offset(exported_btf, m->name_off)) {
            continue;
        }
        // found btf type id
        auto type_id = m->type;
        uint32_t bit_off = 0, bit_sz = 0;
        size_t size;
        if (BTF_INFO_KFLAG(t->info)) {
            bit_off = BTF_MEMBER_BIT_OFFSET(m->offset);
            bit_sz = BTF_MEMBER_BITFIELD_SIZE(m->offset);
        }
        else {
            bit_off = m->offset;
            bit_sz = 0;
        }
        size = (size_t)btf__resolve_size(exported_btf, m->type);
        auto member_type = btf__type_by_id(exported_btf, type_id);
        checked_export_value_member_types.push_back(checked_export_member{
            member, member_type, type_id, bit_off, size, bit_sz });
    }
    return 0;
}

std::string
event_exporter::get_plant_text_checked_types_header(
    std::vector<checked_export_member> &checked_member,
    std::string &prev_header)
{
    // print the time header
    constexpr const char *time_header = "TIME     ";
    std::string header = time_header;
    for (auto &type : checked_export_value_member_types) {
        type.output_header_offset = header.size();
        auto str = type.meta.name;
        std::transform(str.begin(), str.end(), str.begin(), ::toupper);
        header += str;
        if (str.size() < 6) {
            for (size_t i = 0; i < 6 - str.size(); i++) {
                header += " ";
            }
        }
        header += "  ";
    }
    return header;
}

static int
get_btf_type(unsigned int id, const struct btf *btf, std::string &out_type)
{
    DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts, .field_name = "",
                        .indent_level = 2, );
    event_exporter::sprintf_printer printer;
    struct btf_dump *d =
        btf_dump__new(btf, btf_dump_event_printf, &printer, nullptr);
    if (!d) {
        return -1;
    }
    std::unique_ptr<btf_dump, void (*)(btf_dump *)> btf_dumper_keeper{
        d, btf_dump__free
    };
    printer.reset();
    int err = btf_dump__emit_type_decl(d, id, &opts);
    if (err < 0) {
        return err;
    }
    out_type = printer.buffer;
    return 0;
}

int
event_exporter::check_and_push_export_type_btf(
    unsigned int type_id, uint32_t bit_off, uint32_t bit_sz,
    std::vector<checked_export_member> &vec,
    std::optional<export_types_struct_member_meta> member_meta)
{
    auto t = btf__type_by_id(exported_btf, type_id);
    auto size = (size_t)btf__resolve_size(exported_btf, type_id);
    export_types_struct_member_meta meta;
    meta.name = btf_str(exported_btf, t->name_off);
    int err = get_btf_type(type_id, exported_btf, meta.type);
    if (err < 0) {
        return err;
    }
    if (member_meta && member_meta->type == meta.type) {
        // replace generated struct member meta with provide meta data
        meta = *member_meta;
    }
    vec.push_back(
        checked_export_member{ meta, t, type_id, bit_off, size, bit_sz });
    return 0;
}

int
event_exporter::check_sample_types_btf(
    unsigned int type_id, std::vector<checked_export_member> &checked_member,
    std::optional<export_types_struct_meta> members)
{
    auto t = btf__type_by_id(exported_btf, type_id);
    if (!t) {
        std::cerr << "type id " << type_id << " not found" << std::endl;
        return -1;
    }
    if (members
        && members->name != btf__name_by_offset(exported_btf, t->name_off)) {
        std::cerr << "type name " << members->name << " is not matched "
                  << btf__name_by_offset(exported_btf, t->name_off)
                  << std::endl;
        members = std::nullopt;
    }
    if (!btf_is_struct(t)) {
        // single type or array
        return check_and_push_export_type_btf(type_id, 0, 0, checked_member,
                                              std::nullopt);
    }
    btf_member *m = btf_members(t);
    __u16 vlen = BTF_INFO_VLEN(t->info);
    if (members && vlen != members->members.size()) {
        std::cerr << "vlen mismatch: " << vlen << " " << members->members.size()
                  << std::endl;
        members = std::nullopt;
    }
    for (size_t i = 0; i < vlen; i++, m++) {
        // found btf type id
        auto member_type_id = m->type;
        uint32_t bit_off = 0, bit_sz = 0;
        if (BTF_INFO_KFLAG(t->info)) {
            bit_off = BTF_MEMBER_BIT_OFFSET(m->offset);
            bit_sz = BTF_MEMBER_BITFIELD_SIZE(m->offset);
        }
        else {
            bit_off = m->offset;
            bit_sz = 0;
        }
        std::optional<export_types_struct_member_meta> member_meta;
        if (members) {
            // if export types exists, use the export type value for member meta
            // to fix the name of struct fields.
            member_meta = members->members[i];
        }
        auto err = check_and_push_export_type_btf(
            member_type_id, bit_off, bit_sz, checked_member, member_meta);
        if (err < 0) {
            return err;
        }
    }
    return 0;
}

static const std::map<std::string, event_exporter::sample_map_type>
    sample_map_type_map = {
        { "linear_hist", event_exporter::sample_map_type::linear_hist },
        { "log2_hist", event_exporter::sample_map_type::log2_hist },
    };

int
event_exporter::check_and_create_key_value_format(
    unsigned int key_type_id, unsigned int value_type_id,
    map_sample_meta sample_config,
    std::vector<export_types_struct_meta> &export_types, const btf *btf_data)
{
    std::optional<export_types_struct_meta> member;
    if (export_types.size() > 1) {
        std::cerr
            << "Warning: mutiple export types not supported now. use the first "
               "struct as output event."
            << std::endl;
    }
    if (export_types.size() == 1) {
        member = export_types[0];
    }
    exported_btf = btf_data;
    // TODO: check the key btf type with export_types_struct_meta
    if (check_sample_types_btf(key_type_id, checked_export_key_member_types,
                               std::nullopt)
        < 0) {
        std::cerr << "sample key type check failed" << std::endl;
        return -1;
    }
    if (check_sample_types_btf(value_type_id, checked_export_value_member_types,
                               member)
        < 0) {
        std::cerr << "sample value type check failed" << std::endl;
        return -1;
    }
    sample_map_config = sample_config;
    sample_map_type map_type = sample_map_type::default_kv;
    if (sample_map_type_map.count(sample_config.type)) {
        map_type = sample_map_type_map.at(sample_config.type);
    }
    else {
        std::cerr << "warning: unknown sample map type: " << sample_config.type
                  << " print key-value as default" << std::endl;
    }
    setup_btf_dumper();
    // setup the internal_event_processor
    switch (format_type) {
        case export_format_type::EXPORT_JSON:
        {
            internal_sample_map_processor =
                std::bind(&event_exporter::print_sample_event_to_json, this,
                          std::placeholders::_1, std::placeholders::_2);
        } break;
        case export_format_type::EXPORT_RAW_EVENT:
            internal_sample_map_processor =
                std::bind(&event_exporter::raw_sample_handler, this,
                          std::placeholders::_1, std::placeholders::_2);
            break;
        case export_format_type::EXPORT_PLANT_TEXT:
            [[fallthrough]];
        default:
        {
            switch (map_type) {
                case sample_map_type::log2_hist:
                    internal_sample_map_processor = std::bind(
                        &event_exporter::print_sample_event_to_log2_hist, this,
                        std::placeholders::_1, std::placeholders::_2);
                    break;
                case sample_map_type::linear_hist:
                    std::cerr << "unimplemented print linear_hist" << std::endl;
                    return -1;
                    break;
                case sample_map_type::default_kv:
                    [[fallthrough]];
                default:
                    internal_sample_map_processor = std::bind(
                        &event_exporter::print_sample_event_to_plant_text, this,
                        std::placeholders::_1, std::placeholders::_2);
                    // print header for plant text events
                    std::string time_header = "TIME     ";
                    auto header = get_plant_text_checked_types_header(
                        checked_export_key_member_types, time_header);
                    header = get_plant_text_checked_types_header(
                        checked_export_value_member_types, header);
                    printer.reset();
                    printer.sprintf_event("%s", header.c_str());
                    printer.export_to_handler_or_print(
                        user_ctx, user_export_event_handler);
                    break;
            }
        } break;
    }
    return 0;
}

int
event_exporter::check_and_create_export_format(
    std::vector<export_types_struct_meta> &export_types, btf *btf_data)
{
    // check if the export types are valid
    if (export_types.size() == 0 || btf_data == nullptr) {
        std::cerr << "No export types or BTF info found" << std::endl;
        return -1;
    }
    if (export_types.size() > 1) {
        std::cerr
            << "Warning: mutiple export types not supported now. use the first "
               "struct as output event."
            << std::endl;
    }
    exported_btf = btf_data;
    if (check_export_types_btf(export_types[0]) < 0) {
        std::cerr << "export type check failed" << std::endl;
        return -1;
    }
    setup_btf_dumper();
    // setup the internal_event_processor
    switch (format_type) {
        case export_format_type::EXPORT_JSON:
        {
            internal_event_processor =
                std::bind(&event_exporter::print_export_event_to_json, this,
                          std::placeholders::_1, std::placeholders::_2);
        } break;
        case export_format_type::EXPORT_RAW_EVENT:
            internal_event_processor =
                std::bind(&event_exporter::raw_event_handler, this,
                          std::placeholders::_1, std::placeholders::_2);
            break;
        case export_format_type::EXPORT_PLANT_TEXT:
            [[fallthrough]];
        default:
            internal_event_processor = std::bind(
                &event_exporter::print_export_event_to_plant_text_with_time,
                this, std::placeholders::_1, std::placeholders::_2);
            std::string time_header = "TIME     ";
            // print header for plant text events
            auto header = get_plant_text_checked_types_header(
                checked_export_value_member_types, time_header);
            printer.reset();
            printer.sprintf_event("%s", header.c_str());
            printer.export_to_handler_or_print(user_ctx,
                                               user_export_event_handler);
            break;
    }
    return 0;
}

int
event_exporter::sprintf_printer::vsprintf_event(const char *fmt, va_list args)
{
    char output_buffer_pointer[EVENT_SIZE];
    int res = vsnprintf(output_buffer_pointer, EVENT_SIZE, fmt, args);
    if (res < 0) {
        return res;
    }
    buffer.append(output_buffer_pointer);
    return res;
}

int
event_exporter::sprintf_printer::snprintf_event(size_t __maxlen,
                                                const char *fmt, ...)
{
    char output_buffer_pointer[EVENT_SIZE];
    if (__maxlen > EVENT_SIZE) {
        __maxlen = EVENT_SIZE;
    }
    va_list args;
    va_start(args, fmt);
    int res = vsnprintf(output_buffer_pointer, __maxlen, fmt, args);
    va_end(args);
    if (res < 0) {
        return res;
    }
    buffer.append(output_buffer_pointer);
    return res;
}

int
event_exporter::sprintf_printer::sprintf_event(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int res = vsprintf_event(fmt, args);
    va_end(args);
    return res;
}

void
event_exporter::sprintf_printer::export_to_handler_or_print(
    void *user_ctx, export_event_handler &user_export_event_handler)
{
    if (user_export_event_handler != nullptr) {
        user_export_event_handler(user_ctx, buffer.data(), buffer.size());
    }
    else {
        // print to stdout if handler not exists
        std::cout << buffer << std::endl;
    }
}

void
event_exporter::setup_btf_dumper(void)
{
    assert(exported_btf);
    struct btf_dump *d =
        btf_dump__new(exported_btf, btf_dump_event_printf, &printer, nullptr);
    if (!d) {
        std::cerr << "Failed to create btf dump" << std::endl;
        return;
    }
    btf_dumper.reset(d);
}

int
event_exporter::print_export_member(const char *event, std::size_t offset,
                                    const checked_export_member &member,
                                    bool is_json)
{
    int res = 0;
    DECLARE_LIBBPF_OPTS(btf_dump_type_data_opts, opts, .compact = true,
                        .skip_names = true, .emit_zeroes = true, );
    if (is_string_type(member.meta.type.c_str())) {
        const char *fmt = "%s";
        if (is_json) {
            fmt = "\"%s\"";
        }
        res = printer.snprintf_event(member.size, fmt, event + offset);
    }
    else if (is_bool_type(member.meta.type.c_str())) {
        res = printer.sprintf_event("%s", *(event + offset) ? "true" : "false");
    }
    else {
        res = btf_dump__dump_type_data(btf_dumper.get(), member.type_id,
                                       event + offset, member.size, &opts);
        if (res < 0) {
            printer.sprintf_event("<unknown>");
        }
    }
    return res;
}

void
event_exporter::dump_value_members_to_json(
    const char *event, std::vector<checked_export_member> &checker_members)
{
    printer.sprintf_event("{");
    for (std::size_t i = 0; i < checker_members.size(); ++i) {
        auto &member = checker_members[i];
        auto offset = member.bit_offset / 8;

        if (member.bit_offset % 8) {
            std::cerr << "bit offset not supported" << std::endl;
            return;
        }
        printer.sprintf_event("\"%s\":", member.meta.name.c_str());
        print_export_member(event, offset, member, true);
        if (i < checker_members.size() - 1) {
            printer.sprintf_event(",");
        }
    }
    printer.sprintf_event("}");
}

void
event_exporter::print_export_event_to_json(const char *event, size_t size)
{
    printer.reset();
    dump_value_members_to_json(event, checked_export_value_member_types);
    printer.export_to_handler_or_print(user_ctx, user_export_event_handler);
}

void
event_exporter::raw_event_handler(const char *event, size_t size)
{
    printer.reset();
    if (user_export_event_handler) {
        user_export_event_handler(user_ctx, event, size);
    }
}

int
event_exporter::print_sample_event_to_plant_text(
    std::vector<char> &key_buffer, std::vector<char> &value_buffer)
{
    struct tm tm;
    char ts[32];
    time_t t;
    int res;

    printer.reset();
    time(&t);
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
    printer.sprintf_event("%-8s ", ts);
    dump_value_members_to_plant_text(key_buffer.data(),
                                     checked_export_key_member_types);
    dump_value_members_to_plant_text(value_buffer.data(),
                                     checked_export_value_member_types);
    printer.export_to_handler_or_print(user_ctx, user_export_event_handler);
    return 0;
}

int
event_exporter::print_sample_event_to_log2_hist(std::vector<char> &key_buffer,
                                                std::vector<char> &value_buffer)
{
    printer.reset();
    const char *value_event_buffer = value_buffer.data();
    assert(value_event_buffer);
    unsigned int *hist_pointer = nullptr;
    int hist_vals_size = 0;

    printer.sprintf_event("key = ");
    dump_value_members_to_plant_text(key_buffer.data(),
                                     checked_export_key_member_types);
    printer.sprintf_event("\n");
    for (const auto &member : checked_export_value_member_types) {
        auto offset = member.bit_offset / 8;
        if (member.bit_offset % 8) {
            std::cerr << "bit offset not supported" << std::endl;
            return -1;
        }
        if (member.meta.name == "slots") {
            assert(offset < value_buffer.size());
            hist_pointer = static_cast<unsigned int *>(
                (void *)(value_event_buffer + offset));
            hist_vals_size = member.size / 4;
            // find slots for hist
        }
        else {
            printer.sprintf_event("%s = ", member.meta.name.c_str());
            print_export_member(value_event_buffer, offset, member, false);
            printer.sprintf_event("\n");
        }
    }
    printer.export_to_handler_or_print(user_ctx, user_export_event_handler);
    if (hist_pointer) {
        print_log2_hist(hist_pointer, hist_vals_size,
                        sample_map_config.unit.c_str());
    }
    else {
        std::cerr << "slots not found." << std::endl;
        return -1;
    }
    return 0;
}

int
event_exporter::raw_sample_handler(std::vector<char> &key_buffer,
                                   std::vector<char> &value_buffer)
{
    printer.reset();
    if (user_export_event_handler) {
        // TODO: use key value for raw event
        user_export_event_handler(user_ctx, value_buffer.data(),
                                  value_buffer.size());
    }
    return 0;
}

int
event_exporter::print_sample_event_to_json(std::vector<char> &key_buffer,
                                           std::vector<char> &value_buffer)
{
    printer.reset();
    printer.sprintf_event("{\"key\":");
    dump_value_members_to_json(key_buffer.data(),
                               checked_export_key_member_types);
    printer.sprintf_event(",\"value\":");
    dump_value_members_to_json(value_buffer.data(),
                               checked_export_value_member_types);
    printer.sprintf_event("}");
    return 0;
}

void
event_exporter::dump_value_members_to_plant_text(
    const char *event, std::vector<checked_export_member> &checker_members)
{
    for (const auto &member : checker_members) {
        // print padding white space if needed
        if (member.output_header_offset > printer.buffer.size()) {
            for (std::size_t i = printer.buffer.size();
                 i < member.output_header_offset; ++i) {
                printer.sprintf_event(" ");
            }
        }
        else {
            printer.sprintf_event(" ");
        }
        auto offset = member.bit_offset / 8;

        if (member.bit_offset % 8) {
            std::cerr << "bit offset not supported" << std::endl;
            return;
        }
        print_export_member(event, offset, member, false);
    }
}

void
event_exporter::print_export_event_to_plant_text_with_time(const char *event,
                                                           size_t size)
{
    struct tm tm;
    char ts[32];
    time_t t;
    int res;

    printer.reset();
    time(&t);
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
    printer.sprintf_event("%-8s ", ts);
    dump_value_members_to_plant_text(event, checked_export_value_member_types);
    printer.export_to_handler_or_print(user_ctx, user_export_event_handler);
}

void
event_exporter::handler_export_events(const char *event, size_t size) const
{
    if (!event) {
        return;
    }
    if (internal_event_processor) {
        internal_event_processor(event, size);
        return;
    }
    else {
        assert(false && "No export event handler!");
    }
}

// handle values from sample map events
int
event_exporter::handler_sample_key_value(std::vector<char> &key_buffer,
                                         std::vector<char> &value_buffer) const
{
    if (internal_sample_map_processor) {
        return internal_sample_map_processor(key_buffer, value_buffer);
    }
    assert(false && "No handler_sample_key_value!");
    return -1;
}

void
event_exporter::set_export_type(export_format_type type,
                                export_event_handler handler, void *ctx)
{
    format_type = type;
    /// preserve the user defined handler
    user_export_event_handler = handler;
    user_ctx = ctx;
}

void
bpf_skeleton::handler_export_events(const char *event, size_t size) const
{
    exporter.handler_export_events(event, size);
}

int
bpf_skeleton::wait_and_poll_to_handler(enum export_format_type type,
                                       export_event_handler handler,
                                       void *ctx) noexcept
{
    exporter.set_export_type(type, handler, ctx);
    int err = 0;
    try {
        err = enter_wait_and_poll();
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        err = -1;
    }
    return err;
}

} // namespace eunomia
