/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

#include "eunomia/eunomia-bpf.hpp"

#define TASK_COMM_LEN 16
#define NAME_MAX 255

struct opensnoop_event {
	/* user terminology for pid: */
	unsigned long long ts = 1000;
	int pid = 20;
	int uid= 1000;
	int ret= 1;
	int flags = 777;
	char comm[TASK_COMM_LEN] = "hello";
	char fname[NAME_MAX] = "/test/hello/opensnoop";
};

int main(int argc, char **argv)
{
  return 0;
}
