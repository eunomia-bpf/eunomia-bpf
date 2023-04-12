#ifndef EUNOMIA_C_H_
#define EUNOMIA_C_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
enum export_format_type {
    EXPORT_PLANT_TEXT,
    EXPORT_JSON,
    EXPORT_RAW_EVENT,
};
struct eunomia_bpf;
struct eunomia_polling_handle;
/// create a new eunomia bpf program from a json file
struct eunomia_bpf* open_eunomia_skel_from_json(const char* json_data,
                                                const char* bpf_object_buffer,
                                                size_t object_size,
                                                char* btf_archive_path);
/// create a new eunomia bpf program from a json file
struct eunomia_bpf* open_eunomia_skel_from_json_package(const char* json_data);
/// create a new eunomia bpf program from a json with btf archive
struct eunomia_bpf* open_eunomia_skel_from_json_package_with_btf(
    const char* json_data,
    char* btf_archive_path);
/// create a new eunomia bpf program from a json with args
struct eunomia_bpf* open_eunomia_skel_from_json_package_with_args(
    const char* json_data,
    char** args,
    int argc,
    char* btf_archive_path);
/// @brief start running the ebpf program
/// @details load and attach the ebpf program to the kernel to run the ebpf
/// program if the ebpf program has maps to export to user space, you need to
/// call the wait and export.
int load_and_attach_eunomia_skel(struct eunomia_bpf* prog);

/// @brief wait for the program to exit and receive data from export maps and
/// send to handlers
/// @details if the program has a ring buffer or perf event to export data
/// to user space, the program will help load the map info and poll the
/// events automatically.
int wait_and_poll_events_to_handler(struct eunomia_bpf* prog,
                                    enum export_format_type type,
                                    void (*handler)(void*,
                                                    const char*,
                                                    size_t size),
                                    void* ctx);

/// @brief stop, detach, and free the memory
/// @warning this function will free the memory of the program
/// it's not reenter-able, and you should not use the program after this
/// function.
void destroy_eunomia_skel(struct eunomia_bpf* prog);

/// @brief get fd of ebpf program or map by name
int get_bpf_fd(struct eunomia_bpf* prog, const char* name);

/// @brief stop, detach, but not clean the memory
void stop_ebpf_program(struct eunomia_bpf* prog);
/// @brief free the memory of the program
void free_bpf_skel(struct eunomia_bpf* prog);
/// @brief merge json config and args and return the new config
int parse_args_to_json_config(const char* json_config,
                              char** args,
                              int argc,
                              char* out_buffer,
                              size_t out_buffer_size);
/// @brief create a polling handle from a ready-to-poll eunomia
eunomia_polling_handle* handle_create(struct eunomia_bpf* prog);
/// @brief pause or resume the poller
void handle_set_pause_state(eunomia_polling_handle* handle, uint8_t pause);
/// @brief Terminate the poller
void handle_terminate(eunomia_polling_handle* handle);
/// @brief Destroy the handler
void handle_destroy(eunomia_polling_handle* handle);
/// @brief Get the error message
void get_error_message(char* str_out, size_t buf_size);
#ifdef __cplusplus
}
#endif

#endif
