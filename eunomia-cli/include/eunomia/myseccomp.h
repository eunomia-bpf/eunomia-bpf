/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef SECCOMP_H
#define SECCOMP_H

#define _GNU_SOURCE 1
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "config.h"
#include "seccomp-bpf.h"
#include "syscall_helper.h"

/// if a system call is not in the list, it will be allowed
bool is_not_allow(const std::vector<uint32_t>& syscall_vec, uint32_t id);

/// install seccomp filter for all syscalls except those in the list
static int install_syscall_filter(const std::vector<uint32_t>& syscall_vec);

int get_syscall_id(std::string syscall_name);

/// Enable Seccomp syscall

/// param seccomp_config type is defined by include/eunomia/config.h
int enable_seccomp_white_list(const seccomp_config& config);

#endif
