#include <eunomia/eunomia-bpf.hpp>
#include <fstream>
#include <iostream>

using namespace eunomia;

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
    eunomia_ebpf_program ebpf_program{json_str};
    if (ebpf_program.run() < 0)
    {
        std::cerr << "Failed to run ebpf program" << std::endl;
        exit(1);
    }
    if (ebpf_program.wait_and_export_to_handler(export_format_type::EXPORT_JSON, print_event) < 0)
    {
        std::cerr << "Failed to wait and print rb" << std::endl;
        exit(1);
    }
    ebpf_program.stop_and_clean();
    return 0;
}
