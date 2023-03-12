/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, zys
 * All rights reserved.
 */
/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

#include "bpf-api.h"
#include "wasm_export.h"

int main(int argc, char* argv_main[]) {
    if (argc != 2 && argc != 3) {
        std::cout << "usage: " << argv_main[0]
                  << " [path of wasm file]  [-j path of json file]"
                  << std::endl;
        return 1;
    }
    if (argc == 2) {
        // run wasm file
        std::ifstream file(argv_main[1]);
        std::vector<uint8_t> wasm_module((std::istreambuf_iterator<char>(file)),
                                         std::istreambuf_iterator<char>());
        int res = wasm_main(wasm_module.data(), wasm_module.size(), argc - 1,
                            argv_main + 1);
        if (res != 0) {
            return 1;
        }
        return 0;
    } else if (argc == 3 && std::strcmp(argv_main[1], "-j") == 0) {
        // run json file
        std::ifstream json_file(argv_main[2]);
        std::vector<unsigned char> json_str(
            (std::istreambuf_iterator<char>(json_file)),
            std::istreambuf_iterator<char>());

        wasm_bpf_program* program = new wasm_bpf_program();
        int res = program->load_bpf_object(json_str.data(), json_str.size());
        if (res < 0) {
            printf("load_bpf_object failed\n");
            delete program;
            return 0;
        }
        res = program->attach_bpf_program("handle_sched_wakeup", NULL);
        if (res < 0) {
            printf("attach_bpf_program failed handle_sched_wakeup\n");
            delete program;
            return -1;
        }
        res = program->attach_bpf_program("handle_sched_wakeup_new", NULL);
        if (res < 0) {
            printf("attach_bpf_program failed\n");
            delete program;
            return -1;
        }
        res = program->attach_bpf_program("sched_switch", NULL);
        if (res < 0) {
            printf("attach_bpf_program failed\n");
            delete program;
            return -1;
        }
        return 0;
    }
}
