#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

/opt/wasi-sdk/bin/clang  \
        --target=wasm32-wasi \
        -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
        --sysroot=/opt/wasi-sdk/share/wasi-sysroot  \
        -Wl,--strip-all,--no-entry \
        -Wl,--allow-undefined \
        -o bootstrap.wasm bootstrap.c
