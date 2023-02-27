/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#include <eunomia/eunomia-bpf.hpp>
#include <fstream>
#include <iostream>

using namespace eunomia;

void print_event(void *ctx, const char *e, size_t size)
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
    bpf_skeleton ebpf_program;
    if (ebpf_program.open_from_json_config(json_str) < 0)
    {
        std::cerr << "load json config failed" << std::endl;
        return -1;
    }
    if (ebpf_program.load_and_attach() < 0)
    {
        std::cerr << "Failed to run ebpf program" << std::endl;
        exit(1);
    }
    if (ebpf_program.wait_and_poll_to_handler(export_format_type::EXPORT_PLANT_TEXT, print_event) < 0)
    {
        std::cerr << "Failed to wait and print rb" << std::endl;
        exit(1);
    }
    ebpf_program.destroy();
    return 0;
}
