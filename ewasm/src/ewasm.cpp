#include "ewasm/ewasm.h"

#include <string>
#include <vector>

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "wasm_export.h"

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

int
ewasm_program::init(std::vector<char> &buffer_vector, std::string &json_env)
{
    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

    static NativeSymbol native_symbols[] = {
        {
            "create_ebpf_program", // the name of WASM function name
            (void *)create_bpf,    // the native function pointer
            "(*~)i", // the function prototype signature, avoid to use i32
            NULL     // attachment is NULL
        },
        {
            "run_ebpf_program", // the name of WASM function name
            (void *)run_bpf,    // the native function pointer
            "(i)i", // the function prototype signature, avoid to use i32
            NULL    // attachment is NULL
        },
        { "wait_and_export_ebpf_program", (void *)wait_and_export_bpf, "(i)i",
          NULL }
    };

    // Native symbols need below registration phase
    init_args.n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
    init_args.native_module_name = "env";
    init_args.native_symbols = native_symbols;

    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    buffer = buffer_vector.data();
    buf_size = buffer_vector.size();

    if (!buffer) {
        printf("Open wasm app file failed.\n");
        return -1;
    }

    module = wasm_runtime_load((uint8_t *)buffer, buf_size, error_buf,
                               sizeof(error_buf));
    if (!module) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        return -1;
    }

    module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                           error_buf, sizeof(error_buf));

    if (!module_inst) {
        printf("Instantiate wasm module failed. error: %s\n", error_buf);
        return -1;
    }

    exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);
    if (!exec_env) {
        printf("Create wasm execution environment failed.\n");
        return -1;
    }
    return call_wasm_init(json_env);
}

int
ewasm_program::init_wasm_functions()
{
    // must allocate buffer from wasm instance memory space (never use pointer
    // from host runtime)
    json_data_wasm_buffer = wasm_runtime_module_malloc(
        module_inst, 100, (void **)&json_data_buffer);
    if (!(wasm_init_func =
              wasm_runtime_lookup_function(module_inst, "init", NULL))) {
        printf("The wasm function init wasm function is not found.\n");
        return -1;
    }

    event_wasm_buffer = wasm_runtime_module_malloc(module_inst, 100,
                                                   (void **)&event_data_buffer);
    if (!(wasm_process_event_func = wasm_runtime_lookup_function(
              module_inst, "process_event", NULL))) {
        printf("The wasm function process_event wasm function is not found.\n");
        return -1;
    }
}

int
ewasm_program::call_wasm_init(std::string &json_env)
{
    strncpy(json_data_buffer, json_env.c_str(), json_env.size());
    wasm_val_t arguments[2] = { { .kind = WASM_I32,
                                  .of.i32 = (int32_t)json_data_wasm_buffer },
                                { .kind = WASM_I32, .of.i32 = 100 } };
    if (wasm_runtime_call_wasm_a(exec_env, wasm_init_func, 1, results, 2,
                                 arguments)) {
        printf("Native finished calling wasm function: init, "
               "returned a formatted string: %s\n",
               json_data_buffer);
    }
    else {
        printf("call wasm function init failed. error: %s\n",
               wasm_runtime_get_exception(module_inst));
        return -1;
    }
    int ret_val;
    ret_val = results[0].of.i32;
    printf("Native finished calling wasm function init(), returned a "
           "int value: %d\n",
           ret_val);
    return ret_val;
}

int
ewasm_program::call_wasm_process_event(const char *e)
{
    strncpy(event_data_buffer, e, strlen(e));
    wasm_val_t arguments[3] = { { .kind = WASM_I32, .of.i32 = ctx },
                                { .kind = WASM_I32,
                                  .of.i32 = (int32_t)event_wasm_buffer },
                                { .kind = WASM_I32, .of.i32 = 100 } };
    if (wasm_runtime_call_wasm_a(exec_env, wasm_process_event_func, 1, results,
                                 3, arguments)) {
        printf("Native finished calling wasm function: process_event, "
               "returned a formatted string: %s\n",
               wasm_process_event_func);
    }
    else {
        printf("call wasm function process_event failed. error: %s\n",
               wasm_runtime_get_exception(module_inst));
        return -1;
    }
    int ret_val;
    ret_val = results[0].of.i32;
    printf("Native finished calling wasm function process_event(), returned a "
           "int value: %d\n",
           ret_val);
    return ret_val;
}

ewasm_program::~ewasm_program()
{
    if (exec_env)
        wasm_runtime_destroy_exec_env(exec_env);
    if (module_inst) {
        if (json_data_wasm_buffer)
            wasm_runtime_module_free(module_inst, json_data_wasm_buffer);
        if (event_wasm_buffer)
            wasm_runtime_module_free(module_inst, event_wasm_buffer);
        wasm_runtime_deinstantiate(module_inst);
    }
    if (module)
        wasm_runtime_unload(module);
    wasm_runtime_destroy();
}
