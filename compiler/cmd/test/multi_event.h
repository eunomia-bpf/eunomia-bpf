/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef EUNOMIA_BPF_EVENT_H
#define EUNOMIA_BPF_EVENT_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event2 {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
};

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;
	struct event2 e3;
};

typedef struct event3 {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
} event3_t;

#endif /* __BOOTSTRAP_H */

#endif /* __update_H */
