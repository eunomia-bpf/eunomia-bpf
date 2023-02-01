#include "ewasm/ewasm.hpp"

#include <string>
#include <vector>

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "wasm_export.h"
#include "wasm-app/native-ewasm.h"

int
ewasm_program::start(std::vector<char> &buffer_vector, std::string &json_env)
{
    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

    static NativeSymbol native_symbols[] = {
        EXPORT_WASM_API_WITH_SIG(create_bpf, "(*~)i"),
        EXPORT_WASM_API_WITH_SIG(run_bpf, "(i)i"),
        EXPORT_WASM_API_WITH_SIG(wait_and_poll_bpf, "(i)i")
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
    buf_size = (uint32_t)buffer_vector.size();

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
    wasm_runtime_set_user_data(exec_env, this);
    if (init_wasm_functions() < 0) {
        printf("Init wasm functions failed.\n");
        return -1;
    }
    wasm_application_execute_main(module_inst, 0, NULL);
    // return call_wasm_init(json_env);
}

int
ewasm_program::init_wasm_functions()
{
    // must allocate buffer from wasm instance memory space (never use pointer
    // from host runtime)
    json_data_wasm_buffer = wasm_runtime_module_malloc(
        module_inst, PROGRAM_BUFFER_SIZE, (void **)&json_data_buffer);
    if (!json_data_wasm_buffer) {
        printf("Allocate memory failed.\n");
        return -1;
    }
    if (!(wasm_init_func =
              wasm_runtime_lookup_function(module_inst, "bpf_main", NULL))) {
        printf("The wasm function main wasm function is not found. Use default "
               "main function instead.\n");
        return -1;
    }

    event_wasm_buffer = wasm_runtime_module_malloc(
        module_inst, EVENT_BUFFER_SIZE, (void **)&event_data_buffer);
    if (!event_wasm_buffer) {
        printf("Allocate memory failed.\n");
        return -1;
    }
    if (!(wasm_process_event_func = wasm_runtime_lookup_function(
              module_inst, "process_event", NULL))) {
        printf("The wasm function process_event wasm function is not found.  "
               "Use default process function instead.\n");
        return 0;
    }
    return 0;
}

int
ewasm_program::call_wasm_init(std::string &json_env)
{
    strncpy(json_data_buffer, json_env.c_str(), PROGRAM_BUFFER_SIZE);
    wasm_val_t arguments[2];
    arguments[0].kind = WASM_I32;
    arguments[0].of.i32 = (int32_t)json_data_wasm_buffer;
    arguments[1].kind = WASM_I32;
    arguments[1].of.i32 = (int)json_env.size();

    if (!wasm_runtime_call_wasm_a(exec_env, wasm_init_func, 1, results, 2,
                                  arguments)) {
        if (strcmp(wasm_runtime_get_exception(module_inst),
                   "Exception: env.exit(0)")
            == 0) {
            return 0;
        }
        printf("call wasm function init failed. error: %s\n",
               wasm_runtime_get_exception(module_inst));
        return -1;
    }
    int ret_val;
    ret_val = results[0].of.i32;
    return ret_val;
}

void
ewasm_program::process_event(const char *e, size_t size)
{
    int res = call_wasm_process_event(e, size);
    if (res < 0) {
        return;
    }
    if (event_handler) {
        event_handler(event_ctx, event_data_buffer);
    }
}

int
ewasm_program::call_wasm_process_event(const char *e, size_t size)
{
    if (!wasm_process_event_func) {
        // ignore the process event and return.
        return 0;
    }
    if (size > EVENT_BUFFER_SIZE) {
        printf("Event size is too big. size: %ld\n", size);
        return 0;
    }
    memcpy(event_data_buffer, e, size);
    wasm_val_t arguments[3];
    arguments[0].kind = WASM_I32;
    arguments[0].of.i32 = (int32_t)wasm_process_ctx;
    arguments[1].kind = WASM_I32;
    arguments[1].of.i32 = (int32_t)event_wasm_buffer;
    arguments[2].kind = WASM_I32;
    arguments[2].of.i32 = (int)size;

    if (!wasm_runtime_call_wasm_a(exec_env, wasm_process_event_func, 1, results,
                                  3, arguments)) {
        printf("call wasm function process_event failed. error: %s\n",
               wasm_runtime_get_exception(module_inst));
        return -1;
    }
    int ret_val;
    ret_val = results[0].of.i32;
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

// simple wrappers for C API
extern "C" {

struct ewasm_bpf {
    ewasm_program prog;
};

struct ewasm_bpf *
new_ewasm_bpf()
{
    return new ewasm_bpf{};
}

int
ewasm_bpf_start(struct ewasm_bpf *ewasm, char *buff, int buff_size,
                char *json_env)
{
    std::vector<char> buff_vec(buff, buff + buff_size);
    std::string env(json_env);
    return ewasm->prog.start(buff_vec, env);
}
}