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
struct btf_dump;
void
btf__free(struct btf *btf);
void
btf_dump__free(struct btf_dump *d);
}

namespace eunomia {
using export_event_handler =
    std::function<void(void *ctx, const char *event, size_t size)>;

/// @brief dump export event in user space
class event_exporter
{
  public:
    class sprintf_printer
    {
      public:
        static const std::size_t EVENT_SIZE = 512;
        std::string buffer;
        void reset(std::size_t size = 2048)
        {
            buffer.reserve(size);
            buffer.clear();
        }
        int sprintf_event(const char *fmt, ...);
        int snprintf_event(size_t __maxlen, const char *fmt, ...);
        int vsprintf_event(const char *fmt, va_list args);
        void export_to_handler_or_print(
            void *user_ctx, export_event_handler &user_export_event_handler);
    };

  private:
    class checked_export_member
    {
      public:
        export_types_struct_member_meta meta;
        const btf_type *type = nullptr;
        std::uint32_t type_id;
        std::uint32_t bit_offset;
        std::size_t size;
        std::uint32_t bit_size;
        std::size_t output_header_offset;
    };
    using internal_event_handler =
        std::function<void(const char *event, size_t size)>;
    using internal_sample_map_handler = std::function<int(
        std::vector<char> &key_buffer, std::vector<char> &value_buffer)>;

    /// @brief export format type
    export_format_type format_type;
    /// user define handler to process export data
    export_event_handler user_export_event_handler = nullptr;
    /// internal handler to process export data to a given format
    internal_event_handler internal_event_processor = nullptr;
    /// internal handler to sample map data to a given format
    internal_sample_map_handler internal_sample_map_processor = nullptr;
    /// export map value types meta data
    std::vector<checked_export_member> checked_export_value_member_types;
    /// export map key types meta data
    std::vector<checked_export_member> checked_export_key_member_types;

    /// @brief  raw btf data
    const btf *exported_btf = nullptr;
    /// user defined export ctx pointer
    void *user_ctx = nullptr;
    sprintf_printer printer;
    std::unique_ptr<btf_dump, void (*)(btf_dump *)> btf_dumper{
        nullptr, btf_dump__free
    };
    map_sample_meta sample_map_config;

    /// @brief check a single type in exported struct and found btf id
    /// @param field field meta data
    /// @param width the width of the type in bytes
    int check_export_types_btf(export_types_struct_meta &member);
    int check_and_push_export_type_btf(
        unsigned int type_id, uint32_t bit_off, uint32_t bit_sz,
        std::vector<checked_export_member> &vec,
        std::optional<export_types_struct_member_meta> member_meta);
    /// @brief check sample map key and value types from btf
    int check_sample_types_btf(
        unsigned int key_type_id,
        std::vector<checked_export_member> &checked_member,
        std::optional<export_types_struct_meta> members);
    /// print the export header meta if needed
    std::string get_plant_text_checked_types_header(
        std::vector<checked_export_member> &checked_member,
        std::string &prev_header);

    void dump_value_members_to_json(
        const char *event, std::vector<checked_export_member> &checker_members);
    void dump_value_members_to_plant_text(
        const char *event, std::vector<checked_export_member> &checker_members);

    /// a default printer to print event data
    void print_export_event_to_plant_text_with_time(const char *event,
                                                    size_t size);
    /// a default printer to pass event data to user defined handler
    void raw_event_handler(const char *event, size_t size);
    ///  printer to print event data to json
    void print_export_event_to_json(const char *event, size_t size);

    /// a default printer to print event data
    int print_sample_event_to_plant_text(std::vector<char> &key_buffer,
                                         std::vector<char> &value_buffer);
    /// a log2_hist printer to print event data to plant text
    int print_sample_event_to_log2_hist(std::vector<char> &key_buffer,
                                        std::vector<char> &value_buffer);
    /// a default printer to pass event data to user defined handler
    int raw_sample_handler(std::vector<char> &key_buffer,
                           std::vector<char> &value_buffer);
    ///  printer to print event data to json
    int print_sample_event_to_json(std::vector<char> &key_buffer,
                                   std::vector<char> &value_buffer);

    void setup_btf_dumper(void);
    int print_export_member(const char *event, std::size_t offset,
                            const checked_export_member &member, bool is_json);
    friend class bpf_skeleton;
    /// print event with meta data;
    /// used for export call backs: ring buffer and perf events
    /// provide a common interface to print the event data
    void handler_export_events(const char *event, size_t size) const;

    // handle values from sample map events
    int handler_sample_key_value(std::vector<char> &key_buffer,
                                 std::vector<char> &value_buffer) const;

  public:
    /// @brief check for types and create export format
    /// @details  the types from ebpf source code and export header
    /// create export formats for correctly print the data,
    /// and used by user space.
    int check_and_create_export_format(
        std::vector<export_types_struct_meta> &export_types,
        struct btf *btf_data);

    enum class sample_map_type {
        /// print the event data as log2_hist plain text
        log2_hist,
        /// print the event data as linear hist plain text
        linear_hist,
        /// print the event data as key-value format in plain text or json
        default_kv,
    };
    /// @brief set export format to key value btf
    int check_and_create_key_value_format(
        unsigned int key_type_id, unsigned int value_type_id,
        map_sample_meta sample_config,
        std::vector<eunomia::export_types_struct_meta> &export_types,
        const btf *btf_data);

    /// @brief set user export event handler to type
    void set_export_type(export_format_type type, export_event_handler handler,
                         void *ctx = nullptr);
};

} // namespace eunomia

#endif // EUNOMIA_EXPORT_EVENTS_HPP_