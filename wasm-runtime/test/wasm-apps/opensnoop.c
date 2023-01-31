/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "wasm-app/wasm-app.h"

#include "opensnoop.h"

/// @brief init the eBPF program
/// @param env_json the env config from input
/// @return 0 on success, -1 on failure, the eBPF program will be terminated in
/// failure case
int
bpf_main(char *env_json, int str_len)
{
    int res = create_bpf(program_data, strlen(program_data));
    if (res < 0) {
        printf("create_bpf failed %d", res);
        return -1;
    }
    res = run_bpf(res);
    if (res < 0) {
        printf("run_bpf failed %d\n", res);
        return -1;
    }
    res = wait_and_poll_bpf(res);
    if (res < 0) {
        printf("wait_and_poll_bpf failed %d\n", res);
        return -1;
    }
    return 0;
}

/// @brief handle the event output from the eBPF program, valid only when
/// wait_and_poll_events is called
/// @param ctx user defined context
/// @param e json event message
/// @return 0 on pass, -1 on block,
/// the event will be send to next handler in chain on success, or dropped in
/// block.
int
process_event(int ctx, char *e, int str_len)
{
    struct event eve;
    unmarshal_struct_event__from_binary(&eve, e);
    printf("%d %d %d %d %s %s\n", eve.pid, eve.uid, eve.ret, eve.flags,
           eve.comm, eve.fname);
    return -1;
}
