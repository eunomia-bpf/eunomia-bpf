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
main(int argc, char **args)
{
    if (argc != 3)
        printf("error: the number of parameters passed is not equal to 2.");
    int str_len = atoi(args[2]);
    char *env_json = args[1];
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