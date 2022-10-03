#ifndef EUNOMIA_EWASM
#define EUNOMIA_EWASM

#include <cstdlib>
#include <vector>
#include <string>
#include "wasm_export.h"

class ewasm_program
{
  public:
    ewasm_program();
    ~ewasm_program();

    int init(std::vector<char> &wasm_buffer, std::string &json_env);

    void process_event(const char *e);
    void register_event_handler(void (*handler)(void *, const char *),
                                void *ctx);

    int create_ebpf_program(char *ebpf_json);
    int run_ebpf_program(int id);
    int wait_and_export_ebpf_program(int id);

  private:
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    uint32_t buf_size, stack_size = 8092, heap_size = 8092;

    wasm_function_inst_t wasm_process_event_func = NULL;
    wasm_function_inst_t wasm_init_func = NULL;

    wasm_val_t results[1] = { { .kind = WASM_F32, .of.f32 = 0 } };

    char global_heap_buf[512 * 1024];
    char *buffer, error_buf[128];

    int ctx = 0;

    int call_wasm_init(std::string &json_env);
    int call_wasm_process_event(const char *e);
    int init_wasm_functions();

    char *json_data_buffer = NULL;
    uint32_t json_data_wasm_buffer = 0;
    char *event_data_buffer = NULL;
    uint32_t event_wasm_buffer = 0;
};

#endif // EUNOMIA_EWASM