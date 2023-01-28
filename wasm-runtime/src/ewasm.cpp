#include "ewasm/ewasm.hpp"

#include <string>
#include <vector>

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "wasm.h"
#include "wasm-app/native-ewasm.h"

extern "C" {
// 传入两个参数，一个共享的program，一个临时的char *ebpf_json
wasm_trap_t* 
create_bpf(void* env, const wasm_val_vec_t* args, wasm_val_vec_t* results) {
    ewasm_program *program = (ewasm_program *)env;
    assert("program is null" && program != nullptr);
    char *ebpf_json = (char *)args->data[0].of.ref;     //?
    results->data[0].kind = WASM_I32;
    results->data[0].of.i32 = program->create_bpf_program(ebpf_json);
    return NULL;
}

// 传入两个参数，一个共享的program，一个临时的int id
wasm_trap_t* 
run_bpf(void* env, const wasm_val_vec_t* args, wasm_val_vec_t* results) {
    ewasm_program *program = (ewasm_program *)env;
    assert("program is null" && program != nullptr);
    int id = (int)args->data[0].of.i32;     //?
    results->data[0].kind = WASM_I32;
    results->data[0].of.i32 = program->run_bpf_program(id);
    return NULL;
}

// 传入两个参数，一个共享的program，一个临时的int id
wasm_trap_t* 
wait_and_poll_bpf(void* env, const wasm_val_vec_t* args, wasm_val_vec_t* results)
{
    ewasm_program *program = (ewasm_program *)env;
    assert("program is null" && program != nullptr);
    int id = (int)args->data[0].of.i32;         //?
    results->data[0].kind = WASM_I32;
    results->data[0].of.i32 = program->wait_and_poll_bpf_program(id);
    return NULL;
}
}


int
ewasm_program::start(std::vector<char> &buffer_vector, std::string &json_env)
{
    engine = wasm_engine_new();
    store = wasm_store_new(engine);

    buf_size = (uint32_t)buffer_vector.size();
    wasm_byte_vec_new_uninitialized(&binary, buf_size);
    binary.data = buffer_vector.data();

    if (!wasm_module_validate(store, &binary)) {
        printf("> Error validating module!\n");
        return 1;
    }

    module = wasm_module_new(store, &binary);
    if (!module) {
        printf("> Error compiling module!\n");
        return 1;
    }

    // Create external print functions.
    // 分别为create_bpf, run_bpf, wait_and_poll_bpf创建对应的三个函数
    wasm_functype_t* create_bpf_type = wasm_functype_new_1_1(
            wasm_valtype_new_anyref(), wasm_valtype_new_i32());
    wasm_func_t* create_bpf_func = wasm_func_new_with_env(store, create_bpf_type, create_bpf, this, NULL);

    wasm_functype_t* run_bpf_type = wasm_functype_new_1_1(
            wasm_valtype_new_i32(), wasm_valtype_new_i32());
    wasm_func_t* run_bpf_func = wasm_func_new_with_env(store, run_bpf_type, run_bpf, this, NULL);

    wasm_functype_t* wait_and_poll_bpf_type = wasm_functype_new_1_1(
            wasm_valtype_new_i32(), wasm_valtype_new_i32());
    wasm_func_t* wait_and_poll_bpf_func = wasm_func_new_with_env(store, wait_and_poll_bpf_type, wait_and_poll_bpf, this, NULL);

    wasm_functype_delete(create_bpf_type);
    wasm_functype_delete(run_bpf_type);
    wasm_functype_delete(wait_and_poll_bpf_type);

    // Instantiate.
    wasm_extern_t* externs[] = { 
        wasm_func_as_extern(create_bpf_func), 
        wasm_func_as_extern(run_bpf_func), 
        wasm_func_as_extern(wait_and_poll_bpf_func) };
    wasm_extern_vec_t imports = WASM_ARRAY_VEC(externs);
    wasm_instance_t* instance =
        wasm_instance_new(store, module, &imports, NULL);
    if (!instance) {
        printf("> Error instantiating module!\n");
        return 1;
    }

    wasm_func_delete(create_bpf_func);
    wasm_func_delete(run_bpf_func);
    wasm_func_delete(wait_and_poll_bpf_func);

    // Extract export.
    wasm_instance_exports(instance, &exports);
    if (exports.size == 0) {
        printf("> Error accessing exports!\n");
        return 1;
    }
    const wasm_func_t* run_func = wasm_extern_as_func(exports.data[0]);
    if (run_func == NULL) {
        printf("> Error accessing export!\n");
        return 1;
    }

    // if (init_wasm_functions() < 0) {
    //     printf("Init wasm functions failed.\n");
    //     return -1;
    // }
    return call_wasm_init(json_env);
}

int
ewasm_program::init_wasm_functions()
{
    // // must allocate buffer from wasm instance memory space (never use pointer
    // // from host runtime)
    // json_data_wasm_buffer = wasm_runtime_module_malloc(
    //     module_inst, PROGRAM_BUFFER_SIZE, (void **)&json_data_buffer);
    // if (!json_data_wasm_buffer) {
    //     printf("Allocate memory failed.\n");
    //     return -1;
    // }
    // if (!(wasm_init_func =
    //           wasm_runtime_lookup_function(module_inst, "bpf_main", NULL))) {
    //     printf("The wasm function main wasm function is not found. Use default "
    //            "main function instead.\n");
    //     return -1;
    // }

    // event_wasm_buffer = wasm_runtime_module_malloc(
    //     module_inst, EVENT_BUFFER_SIZE, (void **)&event_data_buffer);
    // if (!event_wasm_buffer) {
    //     printf("Allocate memory failed.\n");
    //     return -1;
    // }
    // if (!(wasm_process_event_func = wasm_runtime_lookup_function(
    //           module_inst, "process_event", NULL))) {
    //     printf("The wasm function process_event wasm function is not found.  "
    //            "Use default process function instead.\n");
    //     return 0;
    // }
    return 0;
}

int
ewasm_program::call_wasm_init(std::string &json_env)
{
    wasm_val_t as[2];
    as[0].kind = WASM_I32;
    as[0].of.i32 = (int32_t)json_data_wasm_buffer;
    as[1].kind = WASM_I32;
    as[1].of.i32 = (int)json_env.size();
    wasm_val_t rs[1] = { WASM_INIT_VAL};        // ?
    wasm_val_vec_t args = WASM_ARRAY_VEC(as);   // ?
    wasm_val_vec_t results = WASM_ARRAY_VEC(rs);
    // todo: add code about getting runtime excaption
    if (wasm_func_call(run_func, &args, &results)) {
        printf("> Error calling function!\n");
        return 1;
    }

    int ret_val;
    ret_val = results.data[0].of.i32;
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
    // if (!wasm_process_event_func) {
    //     // ignore the process event and return.
    //     return 0;
    // }
    // if (size > EVENT_BUFFER_SIZE) {
    //     printf("Event size is too big. size: %ld\n", size);
    //     return 0;
    // }
    // memcpy(event_data_buffer, e, size);
    // wasm_val_t arguments[3];
    // arguments[0].kind = WASM_I32;
    // arguments[0].of.i32 = (int32_t)wasm_process_ctx;
    // arguments[1].kind = WASM_I32;
    // arguments[1].of.i32 = (int32_t)event_wasm_buffer;
    // arguments[2].kind = WASM_I32;
    // arguments[2].of.i32 = (int)size;

    // if (!wasm_runtime_call_wasm_a(exec_env, wasm_process_event_func, 1, results,
    //                               3, arguments)) {
    //     printf("call wasm function process_event failed. error: %s\n",
    //            wasm_runtime_get_exception(module_inst));
    //     return -1;
    // }
    // int ret_val;
    // ret_val = results[0].of.i32;
    // return ret_val;
    return 0;
}

ewasm_program::~ewasm_program()
{
    wasm_store_delete(store);
    wasm_engine_delete(engine);
    wasm_byte_vec_delete(&binary);
    wasm_module_delete(module);
    wasm_instance_delete(instance);
    wasm_extern_vec_delete(&exports);
    wasm_store_delete(store);
    wasm_engine_delete(engine);

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