#include "eunomia-bpf.h"
#include <iostream>
#include <fstream>

int main() {
    std::ifstream json_file("package.json");
    std::string json_str((std::istreambuf_iterator<char>(json_file)),
                         std::istreambuf_iterator<char>());
    std::cout << json_str << std::endl;

    eunomia_ebpf_program ebpf_program;
    open_ebpf_program_from_json(ebpf_program, json_str);
    run_ebpf_program(ebpf_program);
    stop_ebpf_program(ebpf_program);
    return 0;
}