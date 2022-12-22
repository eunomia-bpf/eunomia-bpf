#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "eunomia-include/wasm-app.h"
#include "eunomia-include/entry.h"
#include "ewasm-skel.h"

static const char *const usages[] = {
    "app [-p PID]",
    NULL,
};

static int target_pid = 0;

int
main(int argc, const char **argv)
{
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_INTEGER('p', "pid", &target_pid, "target pid", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "Template ebpf app.\n", "");
    argc = argparse_parse(&argparse, argc, argv);

    cJSON *program = cJSON_Parse(program_data);
    // add your own arg processing here
    return start_bpf_program(cJSON_PrintUnformatted(program));
}

int
process_event(int ctx, char *e, int str_len)
{
    cJSON *json = cJSON_Parse(e);
    // add your own event processing here
    printf("%s\n", e);
    return -1;
}
