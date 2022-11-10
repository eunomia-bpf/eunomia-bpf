#include <iostream>
#include <thread>

#include "base64.h"
#include "eunomia/eunomia-bpf.hpp"
#include "json.hpp"

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

int
event_exporter::check_export_type_btf(export_types_struct_meta &struct_meta)
{
    auto t = btf__type_by_id(exported_btf.get(), struct_meta.type_id);
    if (!t || !btf_is_struct(t)) {
        std::cerr << "type id " << struct_meta.type_id << " is not a struct"
                  << std::endl;
    }
    btf_member *m = btf_members(t);
    __u16 vlen = BTF_INFO_VLEN(t->info);
    for (size_t i = 0; i < vlen; i++) {
        auto member = struct_meta.members[i];
        if (!member.type_id) {
            // found btf type id
            member.type_id = m->type;
        }
        auto member_type = btf__type_by_id(exported_btf.get(), member.type_id);
        if (member_type->name_off != m[i].name_off) {
            std::cerr << "member name mismatch: "
                      << btf__name_by_offset(exported_btf.get(),
                                             member_type->name_off)
                      << " != "
                      << btf__name_by_offset(exported_btf.get(), m[i].name_off)
                      << std::endl;
            return -1;
        }
        checked_export_member_types.push_back(
            checked_export_member{ member, member_type });
    }
    return 0;
}

void
event_exporter::print_export_types_header(void)
{
    // print the time header
    std::cout << "TIME    ";
    for (auto &type : checked_export_member_types) {
        auto str = type.meta.name;
        std::transform(str.begin(), str.end(), str.begin(), ::toupper);
        std::cout << str << '\t';
    }
    // print the field name endline
    std::cout << std::endl;
}

int
event_exporter::check_for_meta_types_and_create_export_format(
    std::vector<export_types_struct_meta> &export_types, struct btf *btf_data)
{
    // check if the export types are valid
    if (export_types.size() == 0 || btf_data == nullptr) {
        std::cerr << "No export types or BTF info found" << std::endl;
        return -1;
    }
    if (export_types.size() > 1) {
        std::cerr << "mutiple export types not supported now. use the first "
                     "struct as event."
                  << std::endl;
    }
    exported_btf.reset(btf_data);
    if (check_export_type_btf(export_types[0]) < 0) {
        std::cerr << "export type check failed" << std::endl;
        return -1;
    }
    if (user_export_event_handler == nullptr
        && format_type == export_format_type::EXPORT_PLANT_TEXT) {
        print_export_types_header();
    }
    return 0;
}

event_exporter::sprintf_printer::sprintf_printer(std::vector<char> &buffer,
                                                 std::size_t max_size)
{
    buffer.resize(max_size, 0);
    output_buffer_pointer = buffer.data();
    output_buffer_left = buffer.size();
    buffer_base = buffer.data();
}

int
event_exporter::sprintf_printer::update_buffer(int res)
{
    if (res < 0) {
        std::cerr << "Failed to sprint event" << std::endl;
        return res;
    }
    output_buffer_pointer += res;
    output_buffer_left -= static_cast<std::size_t>(res);
    if (output_buffer_left <= 1) {
        std::cerr << "Failed to sprint event, buffer size limited" << std::endl;
        return -1;
    }
    return res;
}

int
event_exporter::sprintf_printer::vsnprintf_event(const char *fmt, va_list args)
{
    int res = vsnprintf(output_buffer_pointer, output_buffer_left, fmt, args);
    return update_buffer(res);
}

int
event_exporter::sprintf_printer::snprintf_event(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int res = vsnprintf(output_buffer_pointer, output_buffer_left, fmt, args);
    va_end(args);
    return update_buffer(res);
}

void
event_exporter::sprintf_printer::export_to_handler_or_print(
    void *user_ctx, export_event_handler &user_export_event_handler)
{
    *output_buffer_pointer = 0;
    if (user_export_event_handler != nullptr) {
        user_export_event_handler(user_ctx, buffer_base);
    }
    else {
        printf("%s\n", buffer_base);
    }
}

static void
btf_dump_event_printf(void *ctx, const char *fmt, va_list args)
{
    auto printer = static_cast<event_exporter::sprintf_printer *>(ctx);
    printer->vsnprintf_event(fmt, args);
}

void
event_exporter::print_export_event_to_json(const char *event)
{
    sprintf_printer printer{ export_event_buffer, EXPORT_BUFFER_SIZE };
    DECLARE_LIBBPF_OPTS(btf_dump_type_data_opts, opts, .skip_names = true,
                        .emit_zeroes = true, );
    DECLARE_LIBBPF_OPTS(btf_dump_opts, dump_opts);
    struct btf_dump *d = btf_dump__new(
        exported_btf.get(), btf_dump_event_printf, &printer, &dump_opts);
    if (!d) {
        std::cerr << "Failed to create btf dump" << std::endl;
        return;
    }
    int res = printer.snprintf_event("{");
    if (res < 0) {
        return;
    }
    for (std::size_t i = 0; i < checked_export_member_types.size(); ++i) {
        auto &member = checked_export_member_types[i];
        auto offset = member.meta.bit_offset / 8;

        if (member.meta.bit_offset % 8) {
            std::cerr << "bit offset not supported" << std::endl;
            return;
        }
        res = printer.snprintf_event("\"%s\":", member.meta.name);
        if (res < 0) {
            return;
        }
        res = btf_dump__dump_type_data(d, member.meta.type_id, event + offset,
                                       member.meta.size, &opts);
        if (i < checked_export_member_types.size() - 1) {
            res = printer.snprintf_event(",");
            if (res < 0) {
                return;
            }
        }
    }
    res = printer.snprintf_event("}");
    if (res < 0) {
        return;
    }
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
event_exporter::print_plant_text_event_with_time(const char *event)
{
    struct tm *tm;
    char ts[32];
    time_t t;
    sprintf_printer printer{ export_event_buffer, EXPORT_BUFFER_SIZE };
    DECLARE_LIBBPF_OPTS(btf_dump_type_data_opts, opts, .skip_names = true,
                        .emit_zeroes = true, );
    DECLARE_LIBBPF_OPTS(btf_dump_opts, dump_opts);
    struct btf_dump *d = btf_dump__new(
        exported_btf.get(), btf_dump_event_printf, &printer, &dump_opts);
    if (!d) {
        std::cerr << "Failed to create btf dump" << std::endl;
        return;
    }

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    int res = printer.snprintf_event("%-8s ", ts);
    if (res < 0) {
        return;
    }

    for (const auto &member : checked_export_member_types) {
        auto offset = member.meta.bit_offset / 8;

        if (member.meta.bit_offset % 8) {
            std::cerr << "bit offset not supported" << std::endl;
            return;
        }
        res = btf_dump__dump_type_data(d, member.meta.type_id, event + offset,
                                       member.meta.size, &opts);
        if (res < 0) {
            std::cerr << "Failed to dump type data" << std::endl;
            return;
        }
        res = printer.snprintf_event("\t");
    }
    printer.export_to_handler_or_print(user_ctx, user_export_event_handler);
}

/// FIXME: output config with lua
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

void
event_exporter::set_export_type(export_format_type type,
                                export_event_handler handler, void *ctx)
{
    format_type = type;
    /// preserve the user defined handler
    user_export_event_handler = handler;
    user_ctx = ctx;
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
            internal_event_processor =
                std::bind(&event_exporter::print_plant_text_event_with_time,
                          this, std::placeholders::_1);
            break;
    }
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
