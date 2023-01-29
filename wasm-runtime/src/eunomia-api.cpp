
#include "ewasm/ewasm.hpp"
#include <cassert>

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <eunomia/eunomia-bpf.hpp>
#include "wasm_c_api.h"

using namespace eunomia;

int
ewasm_program::create_bpf_program(char *ebpf_json)
{
    int id = (int)bpf_program_map.size();
    bpf_program_map.emplace(id, std::make_unique<bpf_skeleton>());
    int res = bpf_program_map[id]->open_from_json_config(ebpf_json);
    if (res < 0) {
        return res;
    }
    return (int)id;
}

int
ewasm_program::run_bpf_program(int id)
{
    auto bpf_program = bpf_program_map.find(id);
    if (bpf_program == bpf_program_map.end()) {
        return -1;
    }
    return bpf_program->second->load_and_attach();
}

void
handle_eunomia_event(void *ctx, const char *e, size_t size)
{
    assert("ctx is null" && ctx != nullptr);
    ewasm_program *program = (ewasm_program *)ctx;
    program->process_event(e, size);
}

int
ewasm_program::wait_and_poll_bpf_program(int id)
{
    auto bpf_program = bpf_program_map.find(id);
    if (bpf_program == bpf_program_map.end()) {
        return -1;
    }
    return bpf_program->second->wait_and_poll_to_handler(
        export_format_type::EXPORT_RAW_EVENT, handle_eunomia_event, this);
}

extern "C" {
// 传入两个参数，一个共享的program，一个临时的char *ebpf_json
wasm_trap_t* 
create_bpf(void* env, const wasm_val_vec_t* args, wasm_val_vec_t* results) {
    ewasm_program *program = (ewasm_program *)env;
    assert("program is null" && program != nullptr);
    char *ebpf_json = (char *)args->data[0].of.ref;
    results->data[0].kind = WASM_I32;
    results->data[0].of.i32 = program->create_bpf_program(ebpf_json);
    return NULL;
}

// 传入两个参数，一个共享的program，一个临时的int id
wasm_trap_t*
run_bpf(void* env, const wasm_val_vec_t* args, wasm_val_vec_t* results) {
    ewasm_program *program = (ewasm_program *)env;
    assert("program is null" && program != nullptr);
    int id = (int)args->data[0].of.i32;
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
    int id = (int)args->data[0].of.i32;
    results->data[0].kind = WASM_I32;
    results->data[0].of.i32 = program->wait_and_poll_bpf_program(id);
    return NULL;
}
}
