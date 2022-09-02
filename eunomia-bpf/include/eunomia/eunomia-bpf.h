#ifndef EUNOMIA_C_H_
#define EUNOMIA_C_H_

#ifdef __cplusplus
extern "C"
{
#endif
  enum export_format_type
  {
    EEXPORT_PLANT_TEXT,
    EEXPORT_JSON,
    EEXPORT_RAW_EVENT,
  };
  struct eunomia_bpf;
  /// create a new eunomia bpf program from a json file
  struct eunomia_bpf* create_ebpf_program_from_json(const char* json_data);
  /// @brief start running the ebpf program
  /// @details load and attach the ebpf program to the kernel to run the ebpf program
  /// if the ebpf program has maps to export to user space, you need to call
  /// the wait and export.
  int run_ebpf_program(struct eunomia_bpf* program);

  /// @brief wait for the program to exit and receive data from export maps and print the data
  /// @details if the program has a ring buffer or perf event to export data
  /// to user space, the program will help load the map info and poll the
  /// events automatically.
  int wait_and_export_ebpf_program(struct eunomia_bpf* program);
  /// @brief wait for the program to exit and receive data from export maps and send to handlers
  int wait_and_export_ebpf_program_to_handler(
      struct eunomia_bpf* program,
      enum export_format_type type,
      void (*handler)(const char*));

  /// @brief stop, detach, and clean up memory
  /// @details This is thread safe with wait_and_export.
  /// it will notify the wait_and_export to exit and
  /// wait until it exits.
  void stop_and_clean_ebpf_program(struct eunomia_bpf* program);
#ifdef __cplusplus
}
#endif

#endif
