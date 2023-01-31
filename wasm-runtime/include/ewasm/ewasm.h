/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#ifndef EWASM_C_H_
#define EWASM_C_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ewasm_bpf;

struct ewasm_bpf* new_ewasm_bpf();

int ewasm_bpf_start(struct ewasm_bpf* ewasm,char* buff, int buff_size, char* json_env);

#ifdef __cplusplus
}
#endif

#endif