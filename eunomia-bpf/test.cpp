#include "eunomia-bpf.h"
#include <iostream>
#include <fstream>

int main()
{
    std::ifstream json_file("package.json");
    std::string json_str((std::istreambuf_iterator<char>(json_file)),
                         std::istreambuf_iterator<char>());
    std::cout << json_str << std::endl;

    eunomia_ebpf_program ebpf_program{json_str};
    ebpf_program.run();
    ebpf_program.wait_and_print_rb();
    ebpf_program.stop_and_clean();
    return 0;
}