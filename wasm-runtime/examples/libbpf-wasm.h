#ifndef _LIBBPF_WASM_H
#define _LIBBPF_WASM_H

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define POLL_TIMEOUT_MS 100

typedef uint64_t bpf_object_skel;

int
wasm_bpf_map_fd_by_name(bpf_object_skel obj, const char *name);
int
wasm_close_bpf_object(bpf_object_skel obj);
bpf_object_skel
wasm_load_bpf_object(const void *obj_buf, int obj_buf_sz);

int
wasm_attach_bpf_program(bpf_object_skel obj, const char *name,
                        const char *attach_target);
int
wasm_bpf_buffer_poll(bpf_object_skel program,
                     int fd, char *data, int max_size, int timeout_ms);

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

struct bpf_map {
    bpf_object_skel obj_ptr;
    char name[64];
};

struct bpf_program {
    bpf_object_skel obj_ptr;
    char name[64];
    char attach_target[128];
};

struct bpf_map_skeleton {
    const char *name;
    struct bpf_map **map;
    void **mmaped;
};

struct bpf_prog_skeleton {
    const char *name;
    struct bpf_program **prog;
};

struct bpf_object_skeleton {
    size_t sz; /* size of this struct, for forward/backward compatibility */
    const char *name;
    const void *data;
    size_t data_sz;

    bpf_object_skel obj;

    int map_cnt;
    int map_skel_sz; /* sizeof(struct bpf_map_skeleton) */
    struct bpf_map_skeleton *maps;

    int prog_cnt;
    int prog_skel_sz; /* sizeof(struct bpf_prog_skeleton) */
    struct bpf_prog_skeleton *progs;
};

static int
bpf_map__fd(const struct bpf_map *map)
{
    return wasm_bpf_map_fd_by_name(map->obj_ptr, map->name);
}
struct bpf_object_open_opts;
int
bpf_object__open_skeleton(struct bpf_object_skeleton *s,
                          const struct bpf_object_open_opts *opts)
{
    assert(s && s->data && s->data_sz);

    for (int i = 0; i < s->map_cnt; i++) {
        struct bpf_map_skeleton *map_skel =
            (void *)s->maps + i * s->map_skel_sz;
        *map_skel->map = calloc(1, sizeof(**map_skel->map));
        if (!*map_skel->map)
            return -1;
        strncpy((*map_skel->map)->name, map_skel->name,
                sizeof((*map_skel->map)->name));
    }

    for (int i = 0; i < s->prog_cnt; i++) {
        struct bpf_prog_skeleton *prog_skel =
            (void *)s->progs + i * s->prog_skel_sz;
        *prog_skel->prog = calloc(1, sizeof(**prog_skel->prog));
        if (!*prog_skel->prog)
            return -1;
        strncpy((*prog_skel->prog)->name, prog_skel->name,
                sizeof((*prog_skel->prog)->name));
    }

    return 0;
}

int
bpf_object__detach_skeleton(struct bpf_object_skeleton *s)
{
	return 0;
}

int
bpf_object__load_skeleton(struct bpf_object_skeleton *s)
{
    assert(s && s->data && s->data_sz);
    s->obj = wasm_load_bpf_object(s->data, s->data_sz);
    if (!s->obj)
        return -1;

    for (int i = 0; i < s->map_cnt; i++) {
        struct bpf_map_skeleton *map_skel =
            (void *)s->maps + i * s->map_skel_sz;
        if (!*map_skel->map)
            return -1;
        (*map_skel->map)->obj_ptr = s->obj;
    }

    for (int i = 0; i < s->prog_cnt; i++) {
        struct bpf_prog_skeleton *prog_skel =
            (void *)s->progs + i * s->prog_skel_sz;
        if (!*prog_skel->prog)
            return -1;
        (*prog_skel->prog)->obj_ptr = s->obj;
    }
    return 0;
}

int
bpf_object__attach_skeleton(struct bpf_object_skeleton *s)
{
    assert(s && s->data && s->data_sz);

    for (int i = 0; i < s->prog_cnt; i++) {
        struct bpf_prog_skeleton *prog_skel =
            (void *)s->progs + i * s->prog_skel_sz;
        if (prog_skel->prog && *prog_skel->prog)
            wasm_attach_bpf_program(s->obj, (*prog_skel->prog)->name,
                               (*prog_skel->prog)->attach_target);
    }
    return 0;
}
void
bpf_object__destroy_skeleton(struct bpf_object_skeleton *s)
{
    if (!s)
        return;

    if (s->obj)
        wasm_close_bpf_object(s->obj);
    free(s->maps);
    free(s->progs);
    free(s);
}

typedef int (*bpf_buffer_sample_fn)(void *ctx, void *data, size_t size);

struct bpf_buffer {
    struct bpf_map *events;
    int fd;
    void *inner;
    bpf_buffer_sample_fn sample_fn;
};

struct bpf_buffer *
bpf_buffer__new(struct bpf_map *events)
{
    struct bpf_buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer)
        return NULL;
    buffer->events = events;
    return buffer;
}

struct bpf_buffer *
bpf_buffer__open(struct bpf_map *events, bpf_buffer_sample_fn sample_cb,
                 void *ctx)
{
    struct bpf_buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer)
        return NULL;
    buffer->events = events;
    buffer->inner = ctx;
    buffer->fd = bpf_map__fd(buffer->events);
    buffer->sample_fn = sample_cb;
    return buffer;
}

int
bpf_buffer__poll(struct bpf_buffer *buffer, int timeout_ms)
{
    assert(buffer && buffer->events && buffer->sample_fn);
    if (timeout_ms <= 0)
        timeout_ms = POLL_TIMEOUT_MS;
    char event_buffer[4096];
    int res = wasm_bpf_buffer_poll(buffer->events->obj_ptr, buffer->fd, event_buffer,
                              4096, timeout_ms);
    if (res < 0) {
        return res;
    }
    buffer->sample_fn(buffer->inner, event_buffer, res);
	return 0;
}

void
bpf_buffer__free(struct bpf_buffer *buffer)
{
    assert(buffer);
    free(buffer);
}

#endif // _LIBBPF_WASM_H