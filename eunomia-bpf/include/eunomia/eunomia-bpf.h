#ifndef EUNOMIA_C_H_
#define EUNOMIA_C_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif
  enum export_format_type
  {
    EXPORT_PLANT_TEXT,
    EXPORT_JSON,
    EXPORT_RAW_EVENT,
  };
  struct eunomia_bpf;
  /// create a new eunomia bpf program from a json file
  struct eunomia_bpf* open_eunomia_skel_from_json(const char *json_data, const char* bpf_object_buffer, size_t object_size);
  /// @brief start running the ebpf program
  /// @details load and attach the ebpf program to the kernel to run the ebpf program
  /// if the ebpf program has maps to export to user space, you need to call
  /// the wait and export.
  int load_and_attach_eunomia_skel(struct eunomia_bpf* prog);

  /// @brief wait for the program to exit and receive data from export maps and print the data
  /// @details if the program has a ring buffer or perf event to export data
  /// to user space, the program will help load the map info and poll the
  /// events automatically.
  int wait_and_poll_events(struct eunomia_bpf* prog);
  /// @brief wait for the program to exit and receive data from export maps and send to handlers
  int wait_and_poll_events_to_handler(
      struct eunomia_bpf* prog,
      enum export_format_type type,
      void (*handler)(void*, const char*),
      void* ctx);

  /// @brief stop, detach, and free the memory
  /// @warning this function will free the memory of the program
  /// it's not reenter-able, and you should not use the program after this function.
  void destroy_eunomia_skel(struct eunomia_bpf* prog);

  /// @brief get fd of ebpf program or map by name
  int get_bpf_fd(struct eunomia_bpf* prog, const char* name);

  /// @brief stop, detach, but not clean the memory
  void stop_ebpf_program(struct eunomia_bpf* prog);
  /// @brief free the memory of the program
  void free_bpf_skel(struct eunomia_bpf* prog);
#ifdef __cplusplus
}
#endif

#endif
