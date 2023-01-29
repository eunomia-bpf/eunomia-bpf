#ifndef EWASM_NATIVE_API_H_
#define EWASM_NATIVE_API_H_

/// c function interface to called from wasm
#ifdef __cplusplus
extern "C" {
#endif
/// @brief create a ebpf program with json data
/// @param ebpf_json
/// @return id on success, -1 on failure
wasm_trap_t* 
create_bpf(void* env, const wasm_val_vec_t* args, wasm_val_vec_t* results);

/// @brief start running the ebpf program
/// @details load and attach the ebpf program to the kernel to run the ebpf
/// program if the ebpf program has maps to export to user space, you need to
/// call the wait and export.
wasm_trap_t* 
run_bpf(void* env, const wasm_val_vec_t* args, wasm_val_vec_t* results);

/// @brief wait for the program to exit and receive data from export maps and
/// print the data
/// @details if the program has a ring buffer or perf event to export data
/// to user space, the program will help load the map info and poll the
/// events automatically.
wasm_trap_t* 
wait_and_poll_bpf(void* env, const wasm_val_vec_t* args, wasm_val_vec_t* results);
#ifdef __cplusplus
}
#endif


/// @brief init the eBPF program
/// @param env_json the env config from input
/// @return 0 on success, -1 on failure, the eBPF program will be terminated in
/// failure case
int
bpf_main(char *env_json, int str_len);

/// @brief handle the event output from the eBPF program, valid only when
/// wait_and_poll_events is called
/// @param ctx user defined context
/// @param e json event message
/// @return 0 on success, -1 on failure,
/// the event will be send to next handler in chain on success, or dropped in
/// failure
int
process_event(int ctx, char *e, int str_len);

#endif // NATIVE_EWASM_H_
