/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, zys
 * All rights reserved.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "bpf-api.h"

struct event {
	unsigned int pid;
	unsigned int tpid;
	int sig;
	int ret;
	char comm[13];
};


int
main(int argc, char **argv)
{
    int err;
    init_libbpf();

    std::ifstream file(
        "/home/yunwei/eunomia-bpf/examples/bpftools/sigsnoop/sigsnoop.bpf.o");
    std::vector<char> object_data((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
    wasm_bpf_program program;
    if (program.load_bpf_object(object_data.data(), object_data.size()) != 0) {
        std::cerr << "failed to load bpf object" << std::endl;
        return -1;
    }
    if (program.attach_bpf_program("kill_entry", NULL) != 0) {
        std::cerr << "failed to run ebpf program kill_entry" << std::endl;
        return -1;
    }
    if (program.attach_bpf_program("kill_exit", NULL) != 0) {
        std::cerr << "failed to run ebpf program kill_exit" << std::endl;
        return -1;
    }
    if (program.attach_bpf_program("tkill_entry", NULL) != 0) {
        std::cerr << "failed to run ebpf program tkill_entry" << std::endl;
        return -1;
    }
    if (program.attach_bpf_program("tkill_exit", NULL) != 0) {
        std::cerr << "failed to run ebpf program tkill_exit" << std::endl;
        return -1;
    }
    int fd = program.bpf_map_fd_by_name("events");
    char buf[4096];
    for (int i = 0; i < 100; i++) {
        if (program.bpf_buffer_poll(fd, buf, 4096, 100) != 0) {
            std::cerr << "failed to wait and print rb" << std::endl;
            return -1;
        }
        struct event *e = (struct event *)buf;
        printf("%d %d %d %d %s\n", e->pid, e->tpid, e->sig, e->ret, e->comm);
    }
    return 0;
}