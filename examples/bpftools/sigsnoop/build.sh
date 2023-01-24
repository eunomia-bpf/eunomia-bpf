#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

WAMR_DIR=${PWD}/../../../third_party/wasm-micro-runtime
INCLUDE_DIR=${PWD}/eunomia-include/

current_dir=$(pwd)

OUT_FILE=sigsnoop.wasm

# use WAMR SDK to build out the .wasm binary
/opt/wasi-sdk/bin/clang  \
        --target=wasm32-wasi \
        -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
        --sysroot=/opt/wasi-sdk/share/wasi-sysroot  \
        -I ${INCLUDE_DIR} \
        -Wl,--allow-undefined-file=${WAMR_DIR}/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt \
        -Wl,--export=all \
        -Wl,--export=bpf_main \
        -Wl,--export=process_event \
        -Wl,--strip-all,--no-entry \
        -Wl,--allow-undefined \
        -o ${OUT_FILE} app.c

