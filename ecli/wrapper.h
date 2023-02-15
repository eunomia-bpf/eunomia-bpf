/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */

#ifndef __BPF_WASM_API_H
#define __BPF_WASM_API_H

/// The main entry, argc and argv will be passed to the wasm module.
int wasm_main(unsigned char *buf, unsigned int size, int argc, char *argv[]);

#endif
