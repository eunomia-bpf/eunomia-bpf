#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "eunomia-include/wasm-app.h"
#include "eunomia-include/entry.h"
#include "ewasm-skel.h"

static const char *sig_name[] = {
	[0] = "N/A",
	[1] = "SIGHUP",
	[2] = "SIGINT",
	[3] = "SIGQUIT",
	[4] = "SIGILL",
	[5] = "SIGTRAP",
	[6] = "SIGABRT",
	[7] = "SIGBUS",
	[8] = "SIGFPE",
	[9] = "SIGKILL",
	[10] = "SIGUSR1",
	[11] = "SIGSEGV",
	[12] = "SIGUSR2",
	[13] = "SIGPIPE",
	[14] = "SIGALRM",
	[15] = "SIGTERM",
	[16] = "SIGSTKFLT",
	[17] = "SIGCHLD",
	[18] = "SIGCONT",
	[19] = "SIGSTOP",
	[20] = "SIGTSTP",
	[21] = "SIGTTIN",
	[22] = "SIGTTOU",
	[23] = "SIGURG",
	[24] = "SIGXCPU",
	[25] = "SIGXFSZ",
	[26] = "SIGVTALRM",
	[27] = "SIGPROF",
	[28] = "SIGWINCH",
	[29] = "SIGIO",
	[30] = "SIGPWR",
	[31] = "SIGSYS",
};

static const char *const usages[] = {
    "sigsnoop [-h] [-x] [-k] [-n] [-p PID] [-s SIGNAL]",
    NULL,
};

static int target_pid = 0;
static int target_signal = 0;
static bool failed_only = false;
static bool kill_only = false;
static bool signal_name = false;

int main(int argc, const char** argv)
{
	struct argparse_option options[] = {
        OPT_HELP(),
        OPT_BOOLEAN('x', "failed", &failed_only, "failed signals only", NULL, 0, 0),
        OPT_BOOLEAN('k', "killed", &kill_only, "kill only", NULL, 0, 0),
        OPT_INTEGER('p', "pid", &target_pid, "target pid", NULL, 0, 0),
		OPT_INTEGER('s', "signal", &target_signal, "target signal", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "Trace standard and real-time signals.\n", "");
    argc = argparse_parse(&argparse, argc, argv);
    
	cJSON *program = cJSON_Parse(program_data);
	program = set_bpf_program_global_var(program, "filtered_pid", cJSON_CreateNumber(target_pid));
	program = set_bpf_program_global_var(program, "target_signal", cJSON_CreateNumber(target_signal));
	program = set_bpf_program_global_var(program, "failed_only", cJSON_CreateBool(failed_only));
	return start_bpf_program(cJSON_PrintUnformatted(program));
}

int process_event(int ctx, char *e, int str_len)
{
	cJSON *json = cJSON_Parse(e);
	int sig = cJSON_GetObjectItem(json, "sig")->valueint;
	const char *name = sig_name[sig];
	cJSON_AddItemToObject(json, "sig_name", cJSON_CreateString(name));
	char *out = cJSON_PrintUnformatted(json);
	printf("%s\n", out);
	strncpy(e, out, str_len);
	cJSON_Delete(json);
	return 0;
}
