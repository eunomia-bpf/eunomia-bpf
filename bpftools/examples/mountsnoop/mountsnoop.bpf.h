/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MOUNTSNOOP_H
#define __MOUNTSNOOP_H

#define TASK_COMM_LEN 16
#define FS_NAME_LEN 8
#define DATA_LEN 512
#define PATH_MAX 4096

struct event
{
	unsigned long long delta;
	unsigned long long flags;
	unsigned int pid;
	unsigned int tid;
	unsigned int mnt_ns;
	int ret;
	char comm[TASK_COMM_LEN];
	char fs[FS_NAME_LEN];
	char src[PATH_MAX];
	char dest[PATH_MAX];
	char data[DATA_LEN];
	enum op
	{
		MOUNT,
		UMOUNT,
	} op;
};

#endif /* __MOUNTSNOOP_H */
