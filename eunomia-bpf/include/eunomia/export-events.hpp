#ifndef EUNOMIA_EXPORT_EVENTS_HPP_
#define EUNOMIA_EXPORT_EVENTS_HPP_

#include <functional>
#include <memory>
#include <vector>

#include "eunomia-meta.hpp"
#include "eunomia-bpf.h"

namespace eunomia {
using internal_event_handler = std::function<void(const char *event)>;
using export_event_handler = std::function<void(void *ctx, const char *event)>;

/// @brief eunomia-bpf exporter for events in user space
class event_exporter
{
  private:
    std::size_t EXPORT_BUFFER_SIZE = 2048;
    std::vector<char> export_event_buffer;
    /// @brief export format type
    export_format_type format_type;
    /// user define handler to process export data
    export_event_handler user_export_event_handler = nullptr;
    /// internal handler to process export data to a given format
    internal_event_handler internal_event_processor = nullptr;
    /// export types meta data
    export_types_struct_meta checked_export_type;
    /// @brief  raw btf data
    std::vector<char> __raw_btf_data;

    /// user defined export ctx pointer
    void *user_ctx = nullptr;

    /// @brief check a single type in exported struct and found btf id
    /// @param field field meta data
    /// @param width the width of the type in bytes
    void check_export_type_member(export_types_struct_member_meta &field,
                                  std::size_t width);
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
        std::vector<export_types_struct_meta> &export_types, std::vector<char> raw_btf_data);

    /// @brief set user export event handler to type
    void set_export_type(export_format_type type, export_event_handler handler,
                         void *ctx = nullptr);
};

} // namespace eunomia

#endif // EUNOMIA_EXPORT_EVENTS_HPP_