/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, zys
 * All rights reserved.
 */

#include <eunomia/eunomia-bpf.hpp>
#include <fstream>
#include <iostream>
#include "wasm_export.h"
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <cstring>

using namespace eunomia;

extern "C" {
int
intToStr(int x, char *str, int str_len, int digit);
int
get_pow(int x, int y);
int32_t
calculate_native(int32_t n, int32_t func1, int32_t func2);
}

void
print_usage(void)
{
    fprintf(stdout, "Options:\r\n");
    fprintf(stdout, "  [path of wasm file] \n");
}

int
main(int argc, char *argv_main[])
{
    static char global_heap_buf[512 * 1024];
    char *buffer, error_buf[128];
    std::vector<char> buffer_vector;
    int opt;
    char *wasm_path = NULL;

    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    uint32_t buf_size, stack_size = 8092, heap_size = 8092;
    wasm_function_inst_t func = NULL;
    wasm_function_inst_t func2 = NULL;
    char *native_buffer = NULL;
    uint32_t wasm_buffer = 0;

    wasm_val_t results[1] = { { .kind = WASM_F32, .of.f32 = 0 } };
    wasm_val_t arguments[3] = {
        { .kind = WASM_I32, .of.i32 = 10 },
        { .kind = WASM_F64, .of.f64 = 0.000101 },
        { .kind = WASM_F32, .of.f32 = 300.002 },
    };
    uint32_t argv3[1] = { 3 };
    // Next we will pass a buffer to the WASM function
    uint32_t argv2[4];
    wasm_function_inst_t func3;

    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));
    if (argc != 2) {
      print_usage();
    }
    wasm_path = argv_main[1];
    std::ifstream json_file(wasm_path);
    buffer_vector = std::vector<char>((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());

    // Define an array of NativeSymbol for the APIs to be exported.
    // Note: the array must be static defined since runtime
    //            will keep it after registration
    // For the function signature specifications, goto the link:
    // https://github.com/bytecodealliance/wasm-micro-runtime/blob/main/doc/export_native_api.md

    static NativeSymbol native_symbols[] = {
        {
            "intToStr", // the name of WASM function name
            (void*)intToStr,   // the native function pointer
            "(i*~i)i",  // the function prototype signature, avoid to use i32
            NULL        // attachment is NULL
        },
        {
            "get_pow", // the name of WASM function name
            (void*)get_pow,   // the native function pointer
            "(ii)i",   // the function prototype signature, avoid to use i32
            NULL       // attachment is NULL
        },
        { "calculate_native", (void*)calculate_native, "(iii)i", NULL }
    };

    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

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
        printf("Open wasm app file [%s] failed.\n", wasm_path);
        goto fail;
    }

    module = wasm_runtime_load((uint8_t*)buffer, buf_size, error_buf, sizeof(error_buf));
    if (!module) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                           error_buf, sizeof(error_buf));

    if (!module_inst) {
        printf("Instantiate wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);
    if (!exec_env) {
        printf("Create wasm execution environment failed.\n");
        goto fail;
    }

    if (!(func = wasm_runtime_lookup_function(module_inst, "generate_float",
                                              NULL))) {
        printf("The generate_float wasm function is not found.\n");
        goto fail;
    }

    // pass 4 elements for function arguments
    if (!wasm_runtime_call_wasm_a(exec_env, func, 1, results, 3, arguments)) {
        printf("call wasm function generate_float failed. %s\n",
               wasm_runtime_get_exception(module_inst));
        goto fail;
    }

    float ret_val;
    ret_val = results[0].of.f32;
    printf("Native finished calling wasm function generate_float(), returned a "
           "float value: %ff\n",
           ret_val);

    // must allocate buffer from wasm instance memory space (never use pointer
    // from host runtime)
    wasm_buffer =
        wasm_runtime_module_malloc(module_inst, 100, (void **)&native_buffer);

    memcpy(argv2, &ret_val, sizeof(float)); // the first argument
    argv2[1] = wasm_buffer; // the second argument is the wasm buffer address
    argv2[2] = 100;         //  the third argument is the wasm buffer size
    argv2[3] = 3; //  the last argument is the digits after decimal point for
                  //  converting float to string

    if (!(func2 = wasm_runtime_lookup_function(module_inst, "float_to_string",
                                               NULL))) {
        printf(
            "The wasm function float_to_string wasm function is not found.\n");
        goto fail;
    }

    if (wasm_runtime_call_wasm(exec_env, func2, 4, argv2)) {
        printf("Native finished calling wasm function: float_to_string, "
               "returned a formatted string: %s\n",
               native_buffer);
    }
    else {
        printf("call wasm function float_to_string failed. error: %s\n",
               wasm_runtime_get_exception(module_inst));
        goto fail;
    }

    func3 =
        wasm_runtime_lookup_function(module_inst, "calculate", NULL);
    if (!func3) {
        printf("The wasm function calculate is not found.\n");
        goto fail;
    }

    if (wasm_runtime_call_wasm(exec_env, func3, 1, argv3)) {
        uint32_t result = *(uint32_t *)argv3;
        printf("Native finished calling wasm function: calculate, return: %d\n",
               result);
    }
    else {
        printf("call wasm function calculate failed. error: %s\n",
               wasm_runtime_get_exception(module_inst));
        goto fail;
    }

fail:
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

int init_eunomia(int argc, char *argv[])
{
  std::string json_str;
  if (argc == 2)
  {
    std::ifstream json_file(argv[1]);
    json_str = std::string((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
  }
  else
  {
    json_str = std::string((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
  }
  std::cout << json_str << std::endl;
  eunomia_ebpf_program ebpf_program{ json_str };
  if (ebpf_program.run())
  {
    std::cerr << "Failed to run ebpf program" << std::endl;
    return -1;
  }
  if (ebpf_program.wait_and_export())
  {
    std::cerr << "Failed to wait and print rb" << std::endl;
    return -1;
  }
  ebpf_program.stop_and_clean();
  return 0;
}