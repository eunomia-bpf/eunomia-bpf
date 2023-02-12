# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Copyright (c) 2023, eunomia-bpf

.PHONY:all
all: eunomia-bpf-runner

eunomia-bpf-runner:
	cd simple-runner && mkdir -p build && cd build && cmake .. && make
	cd simple-wasm-bpf-runner && mkdir -p build && cd build && cmake .. && make

clean:
	rm -rf simple-wasm-bpf-runner/build
	rm -rf simple-runner/build
