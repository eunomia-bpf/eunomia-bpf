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

void
event_exporter::print_export_types_header(void)
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
    // print the field name endline
    std::cout << header << std::endl;
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
    std::cerr << "type: " << meta.type << " name: " << meta.name
              << " size: " << size << std::endl;
    checked_export_value_member_types.push_back(
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
            std::cerr << "member_meta = members->members[i];" << i << std::endl;
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

int
event_exporter::check_and_create_key_value_format(
    unsigned int key_type_id, unsigned int value_type_id,
    sample_map_type map_type,
    std::vector<export_types_struct_meta> &export_types, struct btf *btf_data)
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
    // TODO: check the key type
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
    setup_btf_dumper();
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
    if (user_export_event_handler == nullptr
        && format_type == export_format_type::EXPORT_PLANT_TEXT) {
        print_export_types_header();
    }
    // setup the internal_event_processor
    switch (format_type) {
        case export_format_type::EXPORT_JSON:
        {
            internal_event_processor =
                std::bind(&event_exporter::print_export_event_to_json, this,
                          std::placeholders::_1);
        } break;
        case export_format_type::EXPORT_RAW_EVENT:
            internal_event_processor =
                std::bind(&event_exporter::raw_event_handler, this,
                          std::placeholders::_1);
            break;
        case export_format_type::EXPORT_PLANT_TEXT:
            [[fallthrough]];
        default:
            internal_event_processor = std::bind(
                &event_exporter::print_export_event_to_plant_text_with_time,
                this, std::placeholders::_1);
            break;
    }
    setup_btf_dumper();
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
        user_export_event_handler(user_ctx, buffer.data());
    }
    else {
        std::cout << buffer << std::endl;
    }
}

void
event_exporter::setup_btf_dumper(void)
{
    if (exported_btf == nullptr) {
        std::cerr << "Failed to create btf dump" << std::endl;
        return;
    }
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
event_exporter::print_export_event_to_json(const char *event)
{
    printer.reset();
    int res = printer.sprintf_event("{");
    if (res < 0) {
        return;
    }
    for (std::size_t i = 0; i < checked_export_value_member_types.size(); ++i) {
        auto &member = checked_export_value_member_types[i];
        auto offset = member.bit_offset / 8;

        if (member.bit_offset % 8) {
            std::cerr << "bit offset not supported" << std::endl;
            return;
        }
        res = printer.sprintf_event("\"%s\":", member.meta.name.c_str());
        if (res < 0) {
            return;
        }
        print_export_member(event, offset, member, true);
        if (i < checked_export_value_member_types.size() - 1) {
            res = printer.sprintf_event(",");
            if (res < 0) {
                return;
            }
        }
    }
    printer.sprintf_event("}");
    printer.export_to_handler_or_print(user_ctx, user_export_event_handler);
}

void
event_exporter::raw_event_handler(const char *event)
{
    if (user_export_event_handler) {
        user_export_event_handler(user_ctx, event);
    }
}

void
event_exporter::print_sample_event_to_plant_text(
    std::vector<char> &key_buffer, std::vector<char> &value_buffer)
{
    std::cerr << "print_sample_event_to_plant_text not implemented"
              << std::endl;
}

void
event_exporter::raw_sample_handler(std::vector<char> &key_buffer,
                                   std::vector<char> &value_buffer)
{
    if (user_export_event_handler) {
        // TODO: use key value for raw event
        user_export_event_handler(user_ctx, value_buffer.data());
    }
}

void
event_exporter::print_sample_event_to_json(std::vector<char> &key_buffer,
                                           std::vector<char> &value_buffer)
{
    std::cerr << "print_sample_event_to_json not implemented" << std::endl;
}

void
event_exporter::print_export_event_to_plant_text_with_time(const char *event)
{
    struct tm *tm;
    char ts[32];
    time_t t;
    int res;

    printer.reset();

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    res = printer.sprintf_event("%-8s ", ts);
    if (res < 0) {
        return;
    }

    for (const auto &member : checked_export_value_member_types) {
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
    printer.export_to_handler_or_print(user_ctx, user_export_event_handler);
}

void
event_exporter::handler_export_events(const char *event) const
{
    if (!event) {
        return;
    }
    if (internal_event_processor) {
        internal_event_processor(event);
        return;
    }
    else {
        assert(false && "No export event handler!");
    }
}

// handle values from sample map events
void
event_exporter::handler_sample_key_value(std::vector<char> &key_buffer,
                                         std::vector<char> &value_buffer) const
{
    std::cerr << "handler_sample_key_value not implemented" << std::endl;
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
bpf_skeleton::handler_export_events(const char *event) const
{
    exporter.handler_export_events(event);
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
