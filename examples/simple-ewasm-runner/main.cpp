/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, zys
 * All rights reserved.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

#include "ewasm/ewasm.hpp"
#include "wasm_export.h"

int
main(int argc, char *argv_main[])
{
    if (argc != 2 && argc !=3) {
        std::cout << "usage: " << argv_main[0] << " [path of wasm file]  [-j path of json file]" << std::endl;
        return 1;
    }
    if (argc == 2){
        // run wasm file
        std::vector<char> buffer_vector;
        std::ifstream wasm_file(argv_main[1]);
        buffer_vector =
            std::vector<char>((std::istreambuf_iterator<char>(wasm_file)),
                            std::istreambuf_iterator<char>());
        ewasm_program p;
        std::string json_env =  "{}";
        int res = p.start(buffer_vector, json_env);
        if (res != 0) {
            return 1;
        }
        return 0;
    } else if (argc == 3 && std::strcmp(argv_main[1], "-j")==0){
        // run json file
        std::ifstream json_file(argv_main[2]);
        std::string json_str = std::string((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
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
        return 0;
    } 
}