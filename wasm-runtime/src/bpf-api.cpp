#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>
#include <unistd.h>
#include "bpf-api.h"
#include <errno.h>
#include <asm/unistd.h>

using namespace std;
extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
extern bool
wasm_runtime_call_indirect(wasm_exec_env_t exec_env, uint32_t element_indices,
                           uint32_t argc, uint32_t argv[]);
}
static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

void
init_libbpf(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
}

#define PERF_BUFFER_PAGES 64

typedef int (*bpf_buffer_sample_fn)(void *ctx, void *data, size_t size);

struct bpf_buffer {
    struct bpf_map *events;
    void *inner;
    bpf_buffer_sample_fn fn;
    wasm_exec_env_t exec_env;
    uint32_t ctx;
    uint32_t wasm_sample_function;
    int type;
};

static int
bpf_buffer_sample(void *ctx, void *data, size_t size)
{
    wasm_bpf_program *program = (wasm_bpf_program *)ctx;
    size_t sample_size = size;
    if (program->max_poll_size < size) {
        sample_size = program->max_poll_size;
    }
    memcpy(program->poll_data, data, sample_size);
    wasm_module_inst_t module_inst =
        wasm_runtime_get_module_inst(program->buffer->exec_env);
    uint32_t argv[] = { program->buffer->ctx,
                        wasm_runtime_addr_native_to_app(module_inst,
                                                        program->poll_data),
                        (uint32_t)size };
    auto buffer = program->buffer.get();
    if (!wasm_runtime_call_indirect(buffer->exec_env,
                                    buffer->wasm_sample_function, 3, argv)) {
        printf("call func1 failed\n");
        return 0xDEAD;
    }
    return 0;
}

static void
perfbuf_sample_fn(void *ctx, int cpu, void *data, __u32 size)
{
    bpf_buffer_sample(ctx, data, size);
}

struct bpf_map *
bpf_obj_get_map_by_fd(int fd, bpf_object *obj)
{
    bpf_map *map;
    bpf_object__for_each_map(map, obj)
    {
        if (bpf_map__fd(map) == fd)
            return map;
    }
    return NULL;
}

struct bpf_buffer *
bpf_buffer__new(struct bpf_map *events)
{
    struct bpf_buffer *buffer;
    bool use_ringbuf;
    int type;
    use_ringbuf = bpf_map__type(events) == BPF_MAP_TYPE_RINGBUF;
    if (use_ringbuf) {
        bpf_map__set_autocreate(events, false);
        type = BPF_MAP_TYPE_RINGBUF;
    }
    else {
        bpf_map__set_type(events, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        bpf_map__set_key_size(events, sizeof(int));
        bpf_map__set_value_size(events, sizeof(int));
        type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    }

    buffer = (bpf_buffer *)calloc(1, sizeof(*buffer));
    if (!buffer) {
        errno = ENOMEM;
        return NULL;
    }

    buffer->events = events;
    buffer->type = type;
    return buffer;
}

int
bpf_buffer__open(struct bpf_buffer *buffer, bpf_buffer_sample_fn sample_cb,
                 void *ctx)
{
    int fd, type;
    void *inner;

    fd = bpf_map__fd(buffer->events);
    type = buffer->type;

    switch (type) {
        case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
            buffer->fn = sample_cb;
            inner = perf_buffer__new(fd, PERF_BUFFER_PAGES, perfbuf_sample_fn,
                                     NULL, ctx, NULL);
            break;
        case BPF_MAP_TYPE_RINGBUF:
            inner = ring_buffer__new(fd, sample_cb, ctx, NULL);
            break;
        default:
            return 0;
    }

    if (!inner)
        return -errno;

    buffer->inner = inner;
    return 0;
}

int
bpf_buffer__poll(struct bpf_buffer *buffer, int timeout_ms)
{
    switch (buffer->type) {
        case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
            return perf_buffer__poll((perf_buffer *)buffer->inner, timeout_ms);
        case BPF_MAP_TYPE_RINGBUF:
            return ring_buffer__poll((ring_buffer *)buffer->inner, timeout_ms);
        default:
            return -EINVAL;
    }
}

void
bpf_buffer__free(struct bpf_buffer *buffer)
{
    if (!buffer)
        return;

    switch (buffer->type) {
        case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
            perf_buffer__free((perf_buffer *)buffer->inner);
            break;
        case BPF_MAP_TYPE_RINGBUF:
            ring_buffer__free((ring_buffer *)buffer->inner);
            break;
    }
    free(buffer);
}

#ifndef offsetofend
#define offsetofend(TYPE, FIELD) \
    (offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))
#endif

int
wasm_bpf_program::bpf_map_fd_by_name(const char *name)
{
    return bpf_object__find_map_fd_by_name(obj.get(), name);
}

int
wasm_bpf_program::load_bpf_object(const void *obj_buf, size_t obj_buf_sz)
{
    auto object = bpf_object__open_mem(obj_buf, obj_buf_sz, NULL);
    obj.reset(object);
    return bpf_object__load(object);
}

int
wasm_bpf_program::attach_bpf_program(const char *name,
                                     const char *attach_target)
{
    if (!attach_target) {
        bpf_program__attach(bpf_object__find_program_by_name(obj.get(), name));
    }
    // TODO: attach bpf program by sec name
    bpf_program__attach(bpf_object__find_program_by_name(obj.get(), name));
    return 0;
}

int
wasm_bpf_program::bpf_buffer_poll(wasm_exec_env_t exec_env, int fd,
                                  int32_t sample_func, uint32_t ctx, void *data,
                                  size_t max_size, int timeout_ms)
{
    if (buffer.get() == nullptr) {
        // create buffer
        auto map = bpf_obj_get_map_by_fd(fd, obj.get());
        buffer.reset(bpf_buffer__new(map));
        bpf_buffer__open(buffer.get(), bpf_buffer_sample, this);
        return 0;
    }
    max_poll_size = max_size;
    poll_data = data;
    buffer->exec_env = exec_env;
    buffer->wasm_sample_function = (uint32_t)sample_func;
    buffer->ctx = ctx;

    // poll the buffer
    int res = bpf_buffer__poll(buffer.get(), timeout_ms);
    if (res < 0) {
        return res;
    }
    return 0;
}

int
bpf_map_operate(int fd, enum bpf_map_cmd cmd, void *key, void *value,
                void *next_key, uint64_t flags)
{
    if (cmd < _BPF_MAP_LOOKUP_ELEM || cmd > _BPF_MAP_GET_NEXT_KEY)
        return -1;
    const size_t attr_sz = offsetofend(union bpf_attr, next_key);
    union bpf_attr attr;
    int ret;

    memset(&attr, 0, attr_sz);
    attr.map_fd = (uint32_t)fd;
    attr.key = (uint64_t)key;
    attr.next_key = (uint64_t)next_key;
    attr.value = (uint64_t)value;
    attr.flags = flags;
    ret = (int)syscall(__NR_bpf, cmd, attr, attr_sz);
    return ret < 0 ? -errno : ret;
}
