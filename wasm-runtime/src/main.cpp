/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, zys
 * All rights reserved.
 */
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "bpf-api.h"

#include "wasm_export.h"

extern "C" {
uint64_t
wasm_load_bpf_object(wasm_exec_env_t exec_env, void *obj_buf, int obj_buf_sz)
{
    if (obj_buf_sz <= 0)
        return 0;
    wasm_bpf_program *program = new wasm_bpf_program();
    int res = program->load_bpf_object(obj_buf, (size_t)obj_buf_sz);
    if (res < 0) {
        delete program;
        return 0;
    }
    return (uint64_t)program;
}

int
wasm_close_bpf_object(wasm_exec_env_t exec_env, uint64_t program)
{
    delete  ((wasm_bpf_program *)program);
    return 0;
}

int
wasm_attach_bpf_program(wasm_exec_env_t exec_env, uint64_t program,
                        char *name, char *attach_target)
{
    return ((wasm_bpf_program *)program)->attach_bpf_program(name, attach_target);
}

int
wasm_bpf_buffer_poll(wasm_exec_env_t exec_env, uint64_t program,
                     int fd, char *data, int max_size, int timeout_ms)
{
    return  ((wasm_bpf_program *)program)->bpf_buffer_poll(fd, data, (size_t)max_size, timeout_ms);
}

int
wasm_bpf_map_fd_by_name(wasm_exec_env_t exec_env, uint64_t program,
                        const char *name)
{
    return  ((wasm_bpf_program *)program)->bpf_map_fd_by_name(name);
}

int
wasm_bpf_map_operate(wasm_exec_env_t exec_env, int fd, int cmd,
                     void *key, void *value, void *next_key)
{   
    if (cmd < _BPF_MAP_LOOKUP_ELEM || cmd > _BPF_MAP_GET_NEXT_KEY)
        return -1;
    return bpf_map_operate(fd, (bpf_map_cmd)cmd, key, value, next_key);
}
}

int
main(int argc, char *argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <wasm_object_file>" << std::endl;
        return -1;
    }
    std::ifstream file(argv[1]);
    std::vector<uint8_t> wasm_module((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
    char error_buf[128];
    int opt;
    char *wasm_path = NULL;

    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    uint32_t stack_size = 8092, heap_size = 8092;
    wasm_function_inst_t start_func = NULL;
    char *native_buffer = NULL;
    uint32_t wasm_buffer = 0;

    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    static NativeSymbol native_symbols[] = {
        EXPORT_WASM_API_WITH_SIG(wasm_load_bpf_object, "(*~)I"),
        EXPORT_WASM_API_WITH_SIG(wasm_attach_bpf_program, "(I$$)i"),
        EXPORT_WASM_API_WITH_SIG(wasm_bpf_buffer_poll, "(Ii*~i)i"),
        EXPORT_WASM_API_WITH_SIG(wasm_bpf_map_fd_by_name, "(I$)i"),
        EXPORT_WASM_API_WITH_SIG(wasm_bpf_map_operate, "(ii***)i"),
        EXPORT_WASM_API_WITH_SIG(wasm_close_bpf_object, "(I)i"),
    };

    init_args.mem_alloc_type = Alloc_With_System_Allocator;

    init_args.n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
    init_args.native_module_name = "env";
    init_args.native_symbols = native_symbols;

    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    module = wasm_runtime_load(wasm_module.data(), (uint32_t)wasm_module.size(),
                               error_buf, sizeof(error_buf));
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

    if (!(start_func = wasm_runtime_lookup_wasi_start_function(module_inst))) {
        printf("The generate_float wasm function is not found.\n");
        return -1;
    }
    if (!wasm_runtime_call_wasm(exec_env, start_func, 0, NULL)) {
        printf("Call wasm function generate_float failed. %s\n",
               wasm_runtime_get_exception(module_inst));
        return -1;
    }
    if (exec_env)
        wasm_runtime_destroy_exec_env(exec_env);
    if (module_inst) {
        if (wasm_buffer)
            wasm_runtime_module_free(module_inst, wasm_buffer);
        wasm_runtime_deinstantiate(module_inst);
    }
    if (module)
        wasm_runtime_unload(module);
    wasm_runtime_destroy();
    return 0;
}
