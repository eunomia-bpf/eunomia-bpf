#ifndef EUNOMIA_EXPORT_EVENTS_HPP_
#define EUNOMIA_EXPORT_EVENTS_HPP_

#include <functional>
#include <memory>
#include <vector>

#include "eunomia-meta.hpp"
#include "eunomia-bpf.h"
#include <cstdio>
#include <cstdlib>

extern "C" {
struct btf;
struct btf_type;
void
btf__free(struct btf *btf);
}

namespace eunomia {
using internal_event_handler = std::function<void(const char *event)>;
using export_event_handler = std::function<void(void *ctx, const char *event)>;

/// @brief eunomia-bpf exporter for events in user space
class event_exporter
{
  private:
    class checked_export_member
    {
      public:
        export_types_struct_member_meta meta;
        const btf_type *type = nullptr;
    };
    std::size_t EXPORT_BUFFER_SIZE = 2048;
    std::vector<char> export_event_buffer;
    /// @brief export format type
    export_format_type format_type;
    /// user define handler to process export data
    export_event_handler user_export_event_handler = nullptr;
    /// internal handler to process export data to a given format
    internal_event_handler internal_event_processor = nullptr;
    /// export types meta data
    std::vector<checked_export_member> checked_export_member_types;
    /// @brief  raw btf data
    std::unique_ptr<btf, void (*)(btf *btf)> exported_btf{ nullptr, btf__free };

    /// user defined export ctx pointer
    void *user_ctx = nullptr;

    /// @brief check a single type in exported struct and found btf id
    /// @param field field meta data
    /// @param width the width of the type in bytes
    int check_export_type_btf(export_types_struct_meta &member);
    /// print the export header meta if needed
    void print_export_types_header(void);

    /// a default printer to print event data
    void print_plant_text_event_with_time(const char *event);
    /// a default printer to pass event data to user defined handler
    void raw_event_handler(const char *event);
    ///  printer to print event data to json
    void print_export_event_to_json(const char *event);

    /// export event to json format
    void export_event_to_json(const char *event);

  public:
    class sprintf_printer
    {
      public:
        char *output_buffer_pointer = nullptr;
        std::size_t output_buffer_left = 0;
        char *buffer_base = nullptr;
        sprintf_printer(std::vector<char> &buffer, std::size_t max_size);
        int update_buffer(int res);
        int snprintf_event(const char *fmt, ...);
        int vsnprintf_event(const char *fmt, va_list args);
        void export_to_handler_or_print(
            void *user_ctx, export_event_handler &user_export_event_handler);
    };

    event_exporter(const event_exporter &) = delete;
    event_exporter() = default;
    event_exporter(std::size_t max_buffer_size)
      : EXPORT_BUFFER_SIZE(max_buffer_size)
    {
    }

    /// print event with meta data;
    /// used for export call backs: ring buffer and perf events
    /// provide a common interface to print the event data
    void handler_export_events(const char *event) const;

    /// @brief check for types and create export format
    /// @details  the types from ebpf source code and export header
    /// create export formats for correctly print the data,
    /// and used by user space.
    int check_for_meta_types_and_create_export_format(
        std::vector<export_types_struct_meta> &export_types,
        struct btf *btf_data);

    /// @brief set user export event handler to type
    void set_export_type(export_format_type type, export_event_handler handler,
                         void *ctx = nullptr);
};

} // namespace eunomia

#endif // EUNOMIA_EXPORT_EVENTS_HPP_