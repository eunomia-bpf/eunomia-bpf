/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/// @brief init the eBPF program
/// @param env_json the env config from input
/// @return 0 on success, -1 on failure, the eBPF program will be terminated in
/// failure case
int
main(int argc, char **argv)
{
    printf("init_only: init the eBPF program");
    return 0;
}
