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

enum event_type {
	EVENT_TYPE__ENTER,
	EVENT_TYPE__EXIT,
};

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;
	enum event_type et;
};

#endif /* __BOOTSTRAP_H */

#endif /* __update_H */
