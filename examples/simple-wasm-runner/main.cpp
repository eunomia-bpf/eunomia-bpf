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
    fprintf(stdout, "  [path of wasm file]  [-j <json env>]\n");
}

int
main(int argc, char *argv_main[])
{
    std::vector<char> buffer_vector;
    if (argc != 2) {
        print_usage();
        return 1;
    }
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
}