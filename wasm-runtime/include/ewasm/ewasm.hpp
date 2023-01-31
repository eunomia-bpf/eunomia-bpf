/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#ifndef EUNOMIA_EWASM
#define EUNOMIA_EWASM

#include <cstdlib>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include "wasm_export.h"
#include "eunomia/eunomia-bpf.hpp"

/// @brief ewasm program runtime base on WSMR
class ewasm_program
{
  public:
    ewasm_program() = default;
    ~ewasm_program();
    void register_event_handler(void (*handler)(void *, const char *),
                                void *ctx)
    {
        event_handler = handler;
        event_ctx = ctx;
    }

    int start(std::vector<char> &wasm_buffer, std::string &json_env);

    int create_bpf_program(char *ebpf_json);
    int run_bpf_program(int id);
    int wait_and_poll_bpf_program(int id);
    void process_event(const char *e, size_t size);

  private:
    std::map<int, std::unique_ptr<eunomia::bpf_skeleton>> bpf_program_map;
    wasm_module_t module = nullptr;
    wasm_module_inst_t module_inst = nullptr;
    wasm_exec_env_t exec_env = nullptr;
    uint32_t buf_size, stack_size = 1024 * 128, heap_size = 1024 * 1024 * 2;

    wasm_function_inst_t wasm_process_event_func = nullptr;
    wasm_function_inst_t wasm_init_func = nullptr;

    wasm_val_t results[1];

    char global_heap_buf[1024 * 1024 * 4];
    char *buffer, error_buf[128];

    void *event_ctx = nullptr;
    void (*event_handler)(void *, const char *) = nullptr;

    int wasm_process_ctx;

    char *json_data_buffer = nullptr;
    uint32_t json_data_wasm_buffer = 0;
    char *event_data_buffer = nullptr;
    uint32_t event_wasm_buffer = 0;
    const uint32_t PROGRAM_BUFFER_SIZE = 1024 * 1024;
    const uint32_t EVENT_BUFFER_SIZE = 4096;

    int call_wasm_init(std::string &json_env);
    int call_wasm_process_event(const char *e, size_t size);
    int init_wasm_functions();

    int default_bpf_main();
};

#endif // EUNOMIA_EWASM