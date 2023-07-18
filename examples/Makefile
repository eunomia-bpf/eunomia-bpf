# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Copyright (c) 2023, eunomia-bpf

.PHONY:all
all: eunomia-bpf-runner

eunomia-bpf-runner:
	cd simple-runner-rs && cargo build --release

clean:
	make -C tests clean
