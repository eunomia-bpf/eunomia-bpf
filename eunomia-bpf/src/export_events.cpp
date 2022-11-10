#include <iostream>
#include <thread>

#include "base64.h"
#include "eunomia/eunomia-bpf.hpp"
#include "json.hpp"

extern "C" {
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
}

namespace eunomia {
struct print_type_format_map {
    const char *format;
    const char *type_str;
};

void
event_exporter::check_export_type_member(
    export_types_struct_member_meta &field, std::size_t width)
{
    
}

void
event_exporter::print_export_types_header(void)
{
    // print the time header
    std::cout << "TIME    ";
    for (auto &type : checked_export_types) {
        std::cout << type.name << ' ';
    }
    // print the field name endline
    std::cout << std::endl;
}

int
event_exporter::check_for_meta_types_and_create_export_format(
    std::vector<export_types_struct_meta> &export_types
    , std::vector<char> raw_btf_data)
{
    // check if the export types are valid
    if (export_types.size() == 0 || raw_btf_data.size() == 0) {
        std::cerr << "No export types or BTF info found" << std::endl;
        return -1;
    }
    if (export_types.size() > 1) {
        std::cerr << "mutiple export types not supported now. use the first "
                     "struct as event."
                  << std::endl;
    }
    checked_export_type = export_types[0];
    __raw_btf_data = raw_btf_data;
    if (user_export_event_handler == nullptr
        && format_type == export_format_type::EXPORT_PLANT_TEXT) {
        print_export_types_header();
    }
    return 0;
}

struct sprintf_printer {
    char *output_buffer_pointer = nullptr;
    std::size_t output_buffer_left = 0;
    char *buffer_base = nullptr;
    sprintf_printer(std::vector<char> &buffer, std::size_t max_size)
    {
        buffer.resize(max_size, 0);
        output_buffer_pointer = buffer.data();
        output_buffer_left = buffer.size();
        buffer_base = buffer.data();
    }
    int update_buffer(int res)
    {
        if (res < 0) {
            std::cerr << "Failed to sprint event" << std::endl;
            return res;
        }
        output_buffer_pointer += res;
        output_buffer_left -= static_cast<std::size_t>(res);
        if (output_buffer_left <= 1) {
            std::cerr << "Failed to sprint event, buffer size limited"
                      << std::endl;
            return -1;
        }
        return res;
    }
    int snprintf_event(const char *fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        int res =
            vsnprintf(output_buffer_pointer, output_buffer_left, fmt, args);
        va_end(args);
        return update_buffer(res);
    }
    void export_to_handler_or_print(
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
};

template<typename T>
static int
print_export_field(const char *data, const export_types_struct_member_meta &f,
                   sprintf_printer &recorder)
{
    auto *field = reinterpret_cast<const T *>(data + f.field_offset / 8);
    return std::snprintf(recorder.output_buffer_pointer,
                         recorder.output_buffer_left, f.print_fmt.c_str(),
                         *field);
}

static int
print_export_cstring(const char *data, const export_types_struct_member_meta &f,
                     sprintf_printer &recorder)
{
    auto *field = reinterpret_cast<const char *>(data + f.field_offset / 8);
    return std::snprintf(recorder.output_buffer_pointer,
                         recorder.output_buffer_left, f.print_fmt.c_str(),
                         field);
}

static std::map<std::string,
                std::function<int(const char *data,
                                  const export_types_struct_member_meta &f,
                                  sprintf_printer &recorder)>>
    print_func_lookup_map = { { "i8", print_export_field<uint8_t> },
                              { "i16", print_export_field<uint16_t> },
                              { "i32", print_export_field<uint32_t> },
                              { "i64", print_export_field<uint64_t> },
                              { "i128", print_export_field<__uint128_t> },
                              { "cstring", print_export_cstring } };

void
event_exporter::print_export_event_to_json(const char *event)
{
    sprintf_printer printer{ export_event_buffer, EXPORT_BUFFER_SIZE };

    int res = printer.snprintf_event("{");
    if (res < 0) {
        return;
    }
    for (std::size_t i = 0; i < checked_export_types.size(); ++i) {
        auto &f = checked_export_types[i];
        auto func = print_func_lookup_map.find(f.llvm_type);
        if (func != print_func_lookup_map.end()) {
            res = printer.update_buffer(
                func->second((const char *)event, f, printer));
            if (res < 0) {
                return;
            }
        }
        if (i < checked_export_types.size() - 1) {
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

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    int res = printer.snprintf_event("%-8s ", ts);
    if (res < 0) {
        return;
    }

    for (const auto &f : checked_export_type.members) {
        auto func = print_func_lookup_map.find(f.llvm_type);
        if (func != print_func_lookup_map.end()) {
            res = printer.update_buffer(
                func->second((const char *)event, f, printer));
            if (res < 0) {
                return;
            }
            res = printer.snprintf_event(" ");
            if (res < 0) {
                return;
            }
        }
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
