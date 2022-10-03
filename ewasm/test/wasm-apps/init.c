#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "native-ewasm.h"

/// @brief init the eBPF program
/// @param env_json the env config from input
/// @return 0 on success, -1 on failure, the eBPF program will be terminated in
/// failure case
int
init(char *env_json, int str_len)
{
    printf("calling into init: %s %d", env_json, str_len);
    return 0;
}

/// @brief handle the event output from the eBPF program, valid only when
/// wait_and_export_ebpf_program is called
/// @param ctx user defined context
/// @param e json event message
/// @return 0 on success, -1 on failure,
/// the event will be send to next handler in chain on success, or dropped in
/// failure
int
process_event(int ctx, char *e, int str_len)
{
    printf("event: %s %d ctx: %d\n", e, str_len, ctx);
    return 0;
}
