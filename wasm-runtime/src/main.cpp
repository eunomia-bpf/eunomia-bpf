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
        // {
        //     "intToStr", // the name of WASM function name
        //     intToStr,   // the native function pointer
        //     "(i*~i)i",  // the function prototype signature, avoid to use i32
        //     NULL        // attachment is NULL
        // },
        // {
        //     "get_pow", // the name of WASM function name
        //     get_pow,   // the native function pointer
        //     "(ii)i",   // the function prototype signature, avoid to use i32
        //     NULL       // attachment is NULL
        // },
        // { "calculate_native", calculate_native, "(iii)i", NULL }
    };

    init_args.mem_alloc_type = Alloc_With_System_Allocator;

    // Native symbols need below registration phase
    init_args.n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
    init_args.native_module_name = "env";
    init_args.native_symbols = native_symbols;

    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    module = wasm_runtime_load(wasm_module.data(), wasm_module.size(),
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
