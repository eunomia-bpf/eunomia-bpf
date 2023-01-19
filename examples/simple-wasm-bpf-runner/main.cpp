#include <ewasm/ewasm.hpp>
#include <fstream>
#include <iostream>

void print_event(void *ctx, const char *e)
{
    std::cout << e << std::endl;
}

/// a dummy loader for test
int main(int argc, char *argv[])
{
    std::string json_str;
    if (argc == 2)
    {
        std::ifstream json_file(argv[1]);
        json_str = std::string((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
    }
    else
    {
        std::cout << "usage: " << argv[0] << " <json config file>" << std::endl;
        exit(1);
    }
    ewasm_program p;
    int id = p.create_bpf_program(json_str.data());
    if ( id < 0)
    {
        std::cerr << "load json config failed" << std::endl;
        return -1;
    }
    if (p.run_bpf_program(id) < 0)
    {
        std::cerr << "Failed to run ebpf program" << std::endl;
        exit(1);
    }
    if (p.wait_and_poll_bpf_program(id) < 0)
    {
        std::cerr << "Failed to wait and print rb" << std::endl;
        exit(1);
    }
    // ebpf_program.destroy();
    return 0;
}
