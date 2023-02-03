#ifndef __BPF_WASM_API_H
#define __BPF_WASM_API_H

#include <stdlib.h>

#define POLL_TIMEOUT_MS 100

struct wasm_bpf_program;

int
bpf_map_fd_by_name(struct wasm_bpf_program *obj, const char *name);

struct wasm_bpf_program *
load_bpf_object(const void *obj_buf, size_t obj_buf_sz);
int
attach_bpf_program(struct wasm_bpf_program *obj, const char *name,
                   const char *attach_target);
int
bpf_buffer_poll(struct wasm_bpf_program *obj, int fd, void *data,
                size_t max_size, int timeout_ms);

enum bpf_map_cmd {
    // BPF_MAP_CREATE,
    _BPF_MAP_LOOKUP_ELEM = 1,
    _BPF_MAP_UPDATE_ELEM,
    _BPF_MAP_DELETE_ELEM,
    _BPF_MAP_GET_NEXT_KEY,
};

int
bpf_map_operate(int fd, enum bpf_map_cmd cmd, void *key, void *value,
                void *next_key);

#endif
