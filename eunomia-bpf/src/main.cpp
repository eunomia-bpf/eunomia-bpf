#include <eunomia/eunomia-bpf.hpp>
#include <iostream>
#include <fstream>

/// a dummy loader for test
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cout << "Usage: " << argv[0] << " <json data>" << std::endl;
        return -1;
    }
    eunomia_ebpf_program ebpf_program{argv[1]};
    ebpf_program.run();
    ebpf_program.wait_and_print_rb();
    ebpf_program.stop_and_clean();
    return 0;
}