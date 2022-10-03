
#include "ewasm/ewasm.h"

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <eunomia/eunomia-bpf.hpp>

using namespace eunomia;


extern bool
wasm_runtime_call_indirect(wasm_exec_env_t exec_env, uint32_t element_indices,
                           uint32_t argc, uint32_t argv[]);

extern "C" {
int
create_bpf(wasm_exec_env_t exec_env, char *ebpf_json, int str_len)
{
}

int
run_bpf(wasm_exec_env_t exec_env, int id)
{
}

int
wait_and_export_bpf(wasm_exec_env_t exec_env, int id)
{
}
}


int
init_eunomia(int argc, char *argv[])
{
    std::string json_str;
    if (argc == 2) {
        std::ifstream json_file(argv[1]);
        json_str = std::string((std::istreambuf_iterator<char>(json_file)),
                               std::istreambuf_iterator<char>());
    }
    else {
        json_str = std::string((std::istreambuf_iterator<char>(std::cin)),
                               std::istreambuf_iterator<char>());
    }
    std::cout << json_str << std::endl;
    eunomia_ebpf_program ebpf_program{ json_str };
    if (ebpf_program.run()) {
        std::cerr << "Failed to run ebpf program" << std::endl;
        return -1;
    }
    if (ebpf_program.wait_and_export()) {
        std::cerr << "Failed to wait and print rb" << std::endl;
        return -1;
    }
    ebpf_program.stop_and_clean();
    return 0;
}
