#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "eunomia-include/wasm-app.h"
#include "ewasm-ebpf.h"

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

/// @brief init the eBPF program
/// @param env_json the env config from input
/// @return 0 on success, -1 on failure, the eBPF program will be terminated in
/// failure case
int bpf_main(char *env_json, int str_len)
{
	cJSON *env = cJSON_Parse(env_json);
	if (!env)
	{
		printf("cJSON_Parse failed for env_json.");
	}
	cJSON *program = cJSON_Parse(program_data);
	// get pid config from env
	cJSON *pid = cJSON_GetObjectItem(env, "pid");
	if (pid)
	{
		program = add_runtime_arg_to_bpf_program(program, "filtered_pid", pid);
	}
	return start_bpf_program(cJSON_PrintUnformatted(program));
}

/// @brief handle the event output from the eBPF program, valid only when
/// wait_and_poll_ebpf_program is called
/// @param ctx user defined context
/// @param e json event message
/// @return 0 on pass, -1 on block,
/// the event will be send to next handler in chain on success, or dropped in
/// block.
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
