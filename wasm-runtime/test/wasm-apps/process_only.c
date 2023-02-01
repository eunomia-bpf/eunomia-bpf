#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "wasm-app/wasm-app.h"

#include "opensnoop.h"

int
main(int argc, char **args)
{
    return start_bpf_program(program_data);
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
    printf("TODO: fix parse JSON\n");
    return -1;
}
