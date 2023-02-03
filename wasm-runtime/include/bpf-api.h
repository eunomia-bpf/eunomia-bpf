/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#ifndef __BPF_WASM_API_H
#define __BPF_WASM_API_H

#include <stdlib.h>
#include <limits.h>
#include <memory>

#define POLL_TIMEOUT_MS 100

struct bpf_buffer;
struct bpf_map;

void
bpf_buffer__free(struct bpf_buffer *);

struct bpf_object;
void
bpf_object__close(bpf_object *object);
void init_libbpf(void);

struct wasm_bpf_program {
    std::unique_ptr<bpf_object, void (*)(bpf_object *obj)> obj{
        nullptr, bpf_object__close
    };
    std::unique_ptr<bpf_buffer, void (*)(bpf_buffer *obj)> buffer{
        nullptr, bpf_buffer__free
    };
    void *poll_data;
    size_t max_size;

    int bpf_map_fd_by_name(const char *name);
    int load_bpf_object(const void *obj_buf, size_t obj_buf_sz);
    int attach_bpf_program(const char *name, const char *attach_target);
    int bpf_buffer_poll(int fd, void *data, size_t max_size, int timeout_ms);
};

enum bpf_map_cmd {
    // BPF_MAP_CREATE,
    BPF_MAP_LOOKUP_ELEM = 1,
    BPF_MAP_UPDATE_ELEM,
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
};

int
bpf_map_operate(int fd, enum bpf_map_cmd cmd, void *key, void *value,
                void *next_key);

#endif
