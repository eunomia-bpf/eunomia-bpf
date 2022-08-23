/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef EUNOMIA_BPF_EVENT_H
#define EUNOMIA_BPF_EVENT_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

// TODO: fix hard coded values and types
// TODO: use this as metadata
struct event {
	int pid;
	int ppid;
	unsigned u32_value1;
	unsigned u32_value2;
	unsigned long long u64_value1;
	unsigned long long u64_value2;
	char char_buffer16[TASK_COMM_LEN];
	char char_buffer127[MAX_FILENAME_LEN];
	int bool_value1;
};

#endif /* __update_H */
