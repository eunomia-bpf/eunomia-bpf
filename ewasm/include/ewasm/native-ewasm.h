#ifndef NATIVE_EWASM_H_
#define NATIVE_EWASM_H_

/// c function interface to called from wasm
#ifdef __cplusplus
extern "C" {
#endif
/// @brief create a ebpf program with json data
/// @param ebpf_json
/// @return id on success, -1 on failure
int
create_bpf(char *ebpf_json, int str_len);

/// @brief start running the ebpf program
/// @details load and attach the ebpf program to the kernel to run the ebpf
/// program if the ebpf program has maps to export to user space, you need to
/// call the wait and export.
int
run_bpf(int id);

/// @brief wait for the program to exit and receive data from export maps and
/// print the data
/// @details if the program has a ring buffer or perf event to export data
/// to user space, the program will help load the map info and poll the
/// events automatically.
int
wait_and_export_bpf(int id);
#ifdef __cplusplus
}
#endif

#endif // NATIVE_EWASM_H_
