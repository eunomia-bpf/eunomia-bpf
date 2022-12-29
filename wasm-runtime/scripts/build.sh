#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception



WAMR_DIR=${PWD}/../../third_party/wasm-micro-runtime
INCLUDE_DIR=${PWD}/../include/

current_dir=$(pwd)


for i in $(find "$current_dir" -regex '.*\.c$' ! -regex '.*\.bpf\.c$')
do
APP_SRC="$i"  
OUT_FILE=${i%.*}.wasm
echo "${INCLUDE_DIR}"

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
        -o ${OUT_FILE} ${APP_SRC}


if [ -f ${OUT_FILE} ]; then
        echo "build ${OUT_FILE} success"
else
        echo "build ${OUT_FILE} fail"
fi
done


for i in *.cpp
do
APP_SRC="$i"
OUT_FILE=${i%.*}.wasm

# use WAMR SDK to build out the .wasm binary
/opt/wasi-sdk/bin/clang     \
        --target=wasm32-wasi \
        -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
        --sysroot=/opt/wasi-sdk/share/wasi-sysroot  \
        -I${INCLUDE_DIR} \
        -Wl,--allow-undefined-file=${WAMR_DIR}/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt \
        -Wl,--export=all \
        -Wl,--export=bpf_main \
        -Wl,--export=process_event \
        -Wl,--strip-all,--no-entry \
        -Wl,--allow-undefined \
        -o ${OUT_FILE} ${APP_SRC}


if [ -f ${OUT_FILE} ]; then
        echo "build ${OUT_FILE} success"
else
        echo "build ${OUT_FILE} fail"
fi
done
