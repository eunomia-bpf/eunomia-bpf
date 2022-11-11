#include <eunomia/eunomia-bpf.hpp>
#include <fstream>
#include <iostream>

using namespace eunomia;

/// a simple loader for eunomia bpf program
int
main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <json_config_file> <bpf_object_file>" << std::endl;
        return -1;
    }
    std::ifstream json_file(argv[1]);
    std::string json_str((std::istreambuf_iterator<char>(json_file)),
                         std::istreambuf_iterator<char>());
    std::ifstream bpf_file(argv[2]);
    std::vector<char> bpf_object_buffer(
        (std::istreambuf_iterator<char>(bpf_file)),
        std::istreambuf_iterator<char>());
    bpf_skeleton ebpf_program{ json_str, bpf_object_buffer };
    if (ebpf_program.load_and_attach()) {
        std::cerr << "failed to run ebpf program" << std::endl;
        return -1;
    }
    if (ebpf_program.wait_and_poll_to_handler(export_format_type::EXPORT_PLANT_TEXT,
                                              nullptr, nullptr)) {
        std::cerr << "failed to wait and print rb" << std::endl;
        return -1;
    }
    ebpf_program.destory();
    return 0;
}