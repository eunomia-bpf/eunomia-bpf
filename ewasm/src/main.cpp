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

void
print_usage(void)
{
    fprintf(stdout, "Options:\r\n");
    fprintf(stdout, "  [path of wasm file] \n");
}

int
main(int argc, char *argv_main[])
{
    std::vector<char> buffer_vector;
    int opt;
    char *wasm_path = NULL;

    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));
    if (argc != 2) {
        print_usage();
    }
    wasm_path = argv_main[1];
    std::ifstream json_file(wasm_path);
    buffer_vector =
        std::vector<char>((std::istreambuf_iterator<char>(json_file)),
                          std::istreambuf_iterator<char>());
    ewasm_program p;
    std::string json_env =  "{}";
    p.init(buffer_vector, json_env);
    p.process_event("hello");
    return 0;
}
