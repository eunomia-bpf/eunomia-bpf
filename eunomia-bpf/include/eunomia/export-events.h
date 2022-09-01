#ifndef EUNOMIA_EXPORT_EVENTS_HPP_
#define EUNOMIA_EXPORT_EVENTS_HPP_

#include <functional>
#include <vector>

#include "eunomia-meta.hpp"

namespace eunomia
{

  /// format data
  struct export_type_info
  {
    const char *print_fmt;
    std::size_t field_offset;
    std::size_t width;
    std::string name;
    std::string llvm_type;
  };

  enum class export_format_type
  {
    STDOUT,
    JSON,
  };

  /// @brief eunomia-bpf exporter for events in user space
  class eunomia_event_exporter
  {
   private:
    /// @brief export format type
    export_format_type format_type;
    /// user define handler to process export data
    std::function<void(const char *event)> user_export_event_handler = nullptr;
    /// export types meta data
    std::vector<export_type_info> checked_export_types;

    void check_and_add_export_type(ebpf_rb_export_field_meta_data &field, std::size_t width);
    /// print the export header meta if needed
    void print_export_types_header(void);

    /// a default printer to print event data
    void print_default_export_event_with_time(const char *event);

   public:
    eunomia_event_exporter(const eunomia_event_exporter &) = delete;
    eunomia_event_exporter() = default;

    /// print event with meta data;
    /// used for export call backs: ring buffer and perf events
    /// provide a common interface to print the event data
    void handler_export_events(const char *event) const;

    /// check for types and create export format

    /// check the types from ebpf source code and export header
    /// create export formats for correctly print the data,
    /// and used by user space.
    int check_for_meta_types_and_create_export_format(ebpf_export_types_meta_data &types);

    /// @brief set user export event handler to type
    void set_export_type(export_format_type type);
  };

}  // namespace eunomia

#endif  // EUNOMIA_EXPORT_EVENTS_HPP_