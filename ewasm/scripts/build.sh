#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

CURR_DIR=$PWD
WAMR_DIR=${PWD}/../../third_party/wasm-micro-runtime
OUT_DIR=${PWD}/out
INCLUDE_DIR=${PWD}/../include/

for i in `ls *.c`
do
APP_SRC="$i"
OUT_FILE=${i%.*}.wasm

# use WAMR SDK to build out the .wasm binary
/opt/wasi-sdk/bin/clang     \
        --target=wasm32 -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
        --sysroot=${WAMR_DIR}/wamr-sdk/app/libc-builtin-sysroot  \
        -I${INCLUDE_DIR} \
        -Wl,--allow-undefined-file=${WAMR_DIR}/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt \
        -Wl,--strip-all,--no-entry -nostdlib \
        -Wl,--export=bpf_main \
        -Wl,--export=process_event \
        -Wl,--allow-undefined \
        -o ${OUT_FILE} ${APP_SRC}


if [ -f ${OUT_FILE} ]; then
        echo "build ${OUT_FILE} success"
else
        echo "build ${OUT_FILE} fail"
fi
done
echo "####################build wasm c apps done"


for i in `ls *.cpp`
do
APP_SRC="$i"
OUT_FILE=${i%.*}.wasm

# use WAMR SDK to build out the .wasm binary
/opt/wasi-sdk/bin/clang     \
        --target=wasm32 -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
        --sysroot=${WAMR_DIR}/wamr-sdk/app/libc-builtin-sysroot  \
        -I${INCLUDE_DIR} \
        -Wl,--allow-undefined-file=${WAMR_DIR}/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt \
        -Wl,--strip-all,--no-entry -nostdlib \
        -Wl,--export=bpf_main \
        -Wl,--export=process_event \
        -Wl,--allow-undefined \
        -o ${OUT_FILE} ${APP_SRC}


if [ -f ${OUT_FILE} ]; then
        echo "build ${OUT_FILE} success"
else
        echo "build ${OUT_FILE} fail"
fi
done
echo "####################build wasm cpp apps done"
