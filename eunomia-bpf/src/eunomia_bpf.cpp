/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */
#include <iostream>
#include <thread>

#include "base64.h"
#include "eunomia/eunomia-bpf.hpp"
#include "json.hpp"

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "helpers/map_helpers.h"
#include "helpers/trace_helpers.h"
}

using json = nlohmann::json;
namespace eunomia {
// control the debug info callback from libbpf
static thread_local bool verbose_local = false;
static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !verbose_local)
        return 0;
    return vfprintf(stderr, format, args);
}

int
bpf_skeleton::load_and_attach_prog(void)
{
    int err = 0;

    verbose_local = meta_data.debug_verbose;
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    if (create_prog_skeleton()) {
        std::cerr << "failed to create skeleton from json" << std::endl;
        return -1;
    }
    auto additional_btf_file = getenv("BTF_FILE_PATH");
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, openopts);
    if (additional_btf_file != NULL) {
        openopts.btf_custom_path = strdup(additional_btf_file);
    }
    if (bpf_object__open_skeleton(skeleton.get(), &openopts)) {
        std::cerr << "failed to open skeleton" << std::endl;
        return -1;
    }
    load_section_data();
    /* Load & verify BPF programs */
    err = bpf_object__load_skeleton(skeleton.get());
    if (err) {
        std::cerr << "failed to load skeleton" << std::endl;
        return -1;
    }
    /* Attach tracepoints */
    err = bpf_object__attach_skeleton(skeleton.get());
    if (err) {
        std::cerr << "failed to attach skeleton" << std::endl;
        return -1;
    }
    return 0;
}

/// load and attach the eBPF program to the kernel
int
bpf_skeleton::load_and_attach(void) noexcept
{
    // check the state of the program
    if (state == ebpf_program_state::INVALID) {
        std::cerr << "invalid program state" << std::endl;
        return -1;
    }
    else if (state == ebpf_program_state::RUNNING) {
        return 0;
    }
    int err = 0;
    try {
        err = load_and_attach_prog();
    } catch (const std::exception &e) {
        std::cerr << "Failed to run eBPF program: " << e.what() << std::endl;
        state = ebpf_program_state::INVALID;
    }
    state = ebpf_program_state::RUNNING;
    return err;
}

const std::string &
bpf_skeleton::get_program_name(void) const
{
    return meta_data.bpf_skel.obj_name;
}

static int
handle_print_ringbuf_event(void *ctx, void *data, size_t data_sz)
{
    const char *e = (const char *)(const void *)data;
    const bpf_skeleton *p = (const bpf_skeleton *)ctx;
    if (!p || !e) {
        std::cerr << "empty ctx or events" << std::endl;
        return -1;
    }
    p->handler_export_events(e);
    return 0;
}

int
bpf_skeleton::export_kv_map(struct bpf_map *hists,
                            std::vector<char> &key_buffer,
                            std::vector<char> &value_buffer,
                            const map_sample_meta &sample_config)
{
    int err, fd = bpf_map__fd(hists);
    __u32 lookup_key = -2, next_key;

    while (!bpf_map_get_next_key(fd, &lookup_key, key_buffer.data())) {
        err = bpf_map_lookup_elem(fd, &next_key, value_buffer.data());
        if (err < 0) {
            break;
        }
        exporter.handler_sample_key_value(key_buffer, value_buffer);
        lookup_key = next_key;
    }

    // cleanup maps
    lookup_key = -2;
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_delete_elem(fd, &next_key);
        if (err < 0) {
            fprintf(stderr, "failed to cleanup map : %d\n", err);
            return -1;
        }
        lookup_key = next_key;
    }
    return 0;
}

int
bpf_skeleton::wait_and_sample_map(std::size_t sample_map_id)
{
    int err = 0;
    const auto &map_meta = meta_data.bpf_skel.maps[sample_map_id];
    const map_sample_meta &sample_config = *(map_meta.sample);
    const auto btf_data = get_btf_data();
    if (!btf_data) {
        return -1;
    }

    unsigned int key_type_id = bpf_map__btf_key_type_id(maps[sample_map_id]);
    unsigned int value_type_id =
        bpf_map__btf_value_type_id(maps[sample_map_id]);
    if (exporter.check_and_create_key_value_format(
            key_type_id, value_type_id, sample_config, meta_data.export_types,
            btf_data)
        < 0) {
        std::cerr << "Failed to create print format" << std::endl;
        return -1;
    }

    std::vector<char> key_buffer = {};
    std::vector<char> value_buffer = {};
    key_buffer.resize(btf__resolve_size(btf_data, key_type_id));
    value_buffer.resize(btf__resolve_size(btf_data, value_type_id));

    /* Process events */
    while (!exiting) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(sample_config.interval));
        err = export_kv_map(maps[sample_map_id], key_buffer, value_buffer,
                            sample_config);
        if (err) {
            break;
        }
    }

    return 0;
}

int
bpf_skeleton::wait_and_poll_from_rb(std::size_t rb_map_id)
{
    int err = 0;

    if (exporter.check_and_create_export_format(meta_data.export_types,
                                                get_btf_data())
        < 0) {
        std::cerr << "Failed to create print format" << std::endl;
        return -1;
    }
    auto ring_buffer_pointer = ring_buffer__new(
        bpf_map__fd(maps[rb_map_id]), handle_print_ringbuf_event, this, NULL);
    if (!ring_buffer_pointer) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 0;
    }
    ring_buffer_map.reset(ring_buffer_pointer);

    /* Process events */
    while (!exiting) {
        err =
            ring_buffer__poll(ring_buffer_map.get(), meta_data.poll_timeout_ms);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            return -1;
        }
    }
    return 0;
}

static void
handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const char *e = (const char *)(const void *)data;
    const bpf_skeleton *p = (const bpf_skeleton *)ctx;
    if (!p || !e) {
        std::cerr << "empty ctx or events" << std::endl;
        return;
    }
    p->handler_export_events(e);
}

static void
handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

btf *
bpf_skeleton::get_btf_data(void)
{
    assert(obj);
    auto btf_data = bpf_object__btf(obj);
    if (!btf_data) {
        fprintf(stderr, "no BTF data load\n");
        return nullptr;
    }
    return btf_data;
}

int
bpf_skeleton::wait_and_poll_from_perf_event_array(std::size_t rb_map_id)
{
    int err = 0;

    if (exporter.check_and_create_export_format(meta_data.export_types,
                                                get_btf_data())
        < 0) {
        std::cerr << "Failed to create print format" << std::endl;
        return -1;
    }
    /* setup event callbacks */
    auto perf_buffer_pointer = perf_buffer__new(
        bpf_map__fd(maps[rb_map_id]), meta_data.perf_buffer_pages, handle_event,
        handle_lost_events, this, NULL);
    if (!perf_buffer_pointer) {
        err = -errno;
        fprintf(stderr, "failed to open perf buffer: %d\n", err);
        return err;
    }
    perf_buffer_map.reset(perf_buffer_pointer);

    /* main: poll */
    while (!exiting) {
        err =
            perf_buffer__poll(perf_buffer_map.get(), meta_data.poll_timeout_ms);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
            return err;
        }
        /* reset err to return 0 if exiting */
        err = 0;
    }
    return 0;
}

int
bpf_skeleton::wait_for_no_export_program(void)
{
    // if we don't have a ring buffer, just wait for the program to exit
    std::cerr << "Runing eBPF program..." << std::endl;
    while (!exiting) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}

enum class export_map_type {
    RING_BUFFER,
    PERF_EVENT_ARRAY,
    SAMPLE,
    NO_EXPORT,
};

static void
set_and_warn_existing_export_map(export_map_type &type,
                                 export_map_type new_type)
{
    if (type != export_map_type::NO_EXPORT) {
        std::cerr << "Warning: Multiple export maps found" << std::endl;
    }
    type = new_type;
}

int
bpf_skeleton::check_export_maps(void)
{
    export_map_type type = export_map_type::NO_EXPORT;
    std::size_t map_index = 0;

    for (std::size_t i = 0; i < meta_data.bpf_skel.maps.size(); i++) {
        auto map = maps[i];
        const auto &map_meta = meta_data.bpf_skel.maps[i];
        if (!map) {
            continue;
        }
        else if (map_meta.sample) {
            set_and_warn_existing_export_map(type, export_map_type::SAMPLE);
            map_index = i;
        }
        else if (bpf_map__type(map) == BPF_MAP_TYPE_RINGBUF
                 && !meta_data.export_types.empty()) {
            set_and_warn_existing_export_map(type,
                                             export_map_type::RING_BUFFER);
            map_index = i;
        }
        else if (bpf_map__type(map) == BPF_MAP_TYPE_PERF_EVENT_ARRAY
                 && !meta_data.export_types.empty()) {
            set_and_warn_existing_export_map(type,
                                             export_map_type::PERF_EVENT_ARRAY);
            map_index = i;
        }
    }
    if (meta_data.debug_verbose) {
        std::cerr << "eunomia-bpf: wait and poll events type " << (int)type
                  << " on map id: " << map_index << std::endl;
    }
    switch (type) {
        case export_map_type::RING_BUFFER:
            return wait_and_poll_from_rb(map_index);
        case export_map_type::PERF_EVENT_ARRAY:
            return wait_and_poll_from_perf_event_array(map_index);
        case export_map_type::SAMPLE:
            return wait_and_sample_map(map_index);
        case export_map_type::NO_EXPORT:
            return wait_for_no_export_program();
    }
    return -1;
}

int
bpf_skeleton::enter_wait_and_poll(void)
{
    int err;
    exiting = false;
    // check the state
    if (state != ebpf_program_state::RUNNING) {
        std::cerr << "ebpf program is not running" << std::endl;
        return -1;
    }
    // help the wait_and_print work with stop correctly in multi-thread
    std::lock_guard<std::mutex> guard(exit_mutex);
    return check_export_maps();
}

int
bpf_skeleton::wait_and_poll(void) noexcept
{
    exporter.set_export_type(export_format_type::EXPORT_PLANT_TEXT, nullptr);
    int err = 0;
    try {
        err = enter_wait_and_poll();
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        err = -1;
    }
    return err;
}

void
bpf_skeleton::destroy() noexcept
{
    if (state != ebpf_program_state::RUNNING) {
        return;
    }
    exiting = true;
    /// wait until poll has exit
    std::lock_guard<std::mutex> guard(exit_mutex);
    state = ebpf_program_state::STOPPED;
}

int
bpf_skeleton::create_prog_skeleton(void)
{
    struct bpf_object_skeleton *s;
    skeleton = nullptr;

    s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
    if (!s)
        return -1;

    s->sz = sizeof(*s);
    s->name = meta_data.bpf_skel.obj_name.c_str();

    /* maps */
    s->map_cnt = 0;
    s->map_skel_sz = sizeof(*s->maps);
    s->maps = (struct bpf_map_skeleton *)calloc(meta_data.bpf_skel.maps.size(),
                                                (size_t)s->map_skel_sz);
    if (!s->maps)
        goto err;

    maps.resize(meta_data.bpf_skel.maps.size());
    for (std::size_t i = 0; i < meta_data.bpf_skel.maps.size(); i++) {
        if (meta_data.bpf_skel.maps[i].ident == "rodata") {
            s->maps[s->map_cnt].mmaped = (void **)&rodata_buffer;
        }
        else if (meta_data.bpf_skel.maps[i].ident == "bss") {
            s->maps[s->map_cnt].mmaped = (void **)&bss_buffer;
        }
        s->maps[s->map_cnt].name = meta_data.bpf_skel.maps[i].name.c_str();
        s->maps[s->map_cnt].map = &maps[i];
        s->map_cnt++;
    }

    /* programs */
    s->prog_skel_sz = sizeof(*s->progs);
    s->progs = (struct bpf_prog_skeleton *)calloc(
        meta_data.bpf_skel.progs.size(), (size_t)s->prog_skel_sz);
    if (!s->progs)
        goto err;
    progs.resize(meta_data.bpf_skel.progs.size());
    links.resize(meta_data.bpf_skel.progs.size());
    s->prog_cnt = 0;
    for (std::size_t i = 0; i < meta_data.bpf_skel.progs.size(); i++) {
        auto &prog = meta_data.bpf_skel.progs[i];
        s->progs[s->prog_cnt].name = prog.name.c_str();
        s->progs[s->prog_cnt].prog = &progs[i];
        if (prog.link) {
            s->progs[s->prog_cnt].link = &links[i];
        }
        s->prog_cnt++;
    }

    s->data_sz = __bpf_object_buffer.size();
    s->data = (void *)__bpf_object_buffer.data();

    s->obj = &obj;
    skeleton.reset(s);
    return 0;
err:
    bpf_object__destroy_skeleton(s);
    return -1;
}

int
bpf_skeleton::get_fd(const char *name) const noexcept
{
    for (std::size_t i = 0; i < meta_data.bpf_skel.maps.size(); i++) {
        if (meta_data.bpf_skel.maps[i].name == name) {
            return bpf_map__fd(maps[i]);
        }
    }
    for (std::size_t i = 0; i < meta_data.bpf_skel.progs.size(); i++) {
        if (meta_data.bpf_skel.progs[i].name == name) {
            return bpf_program__fd(progs[i]);
        }
    }
    return -1;
}

} // namespace eunomia

// simple wrappers for C API
extern "C" {
struct eunomia_bpf {
    eunomia::bpf_skeleton program;
};
struct eunomia_bpf *
open_eunomia_skel_from_json(const char *json_data,
                            const char *bpf_object_buffer, size_t object_size)
{
    struct eunomia_bpf *bpf = new eunomia_bpf{ eunomia::bpf_skeleton() };
    if (!bpf) {
        return nullptr;
    }
    if (bpf->program.open_from_json_config(
            json_data, std::vector<char>{ bpf_object_buffer,
                                          bpf_object_buffer + object_size })
        < 0) {
        delete bpf;
        return nullptr;
    }
    return bpf;
}

struct eunomia_bpf *
open_eunomia_skel_from_json_package(const char *json_data)
{
    struct eunomia_bpf *bpf = new eunomia_bpf{ eunomia::bpf_skeleton() };
    if (!bpf) {
        return nullptr;
    }
    if (bpf->program.open_from_json_config(json_data) < 0) {
        delete bpf;
        return nullptr;
    }
    return bpf;
}

int
load_and_attach_eunomia_skel(struct eunomia_bpf *prog)
{
    if (!prog) {
        return -1;
    }
    return prog->program.load_and_attach();
}

int
wait_and_poll_events(struct eunomia_bpf *prog)
{
    if (!prog) {
        return -1;
    }
    return prog->program.wait_and_poll();
}

int
wait_and_poll_events_to_handler(struct eunomia_bpf *prog,
                                enum export_format_type type,
                                void (*handler)(void *, const char *),
                                void *ctx)
{
    if (!prog || !handler) {
        return -1;
    }
    return prog->program.wait_and_poll_to_handler(type, handler, ctx);
}

void
destroy_eunomia_skel(struct eunomia_bpf *prog)
{
    if (!prog) {
        return;
    }
    prog->program.destroy();
    delete prog;
}

/// @brief stop the ebpf program
void
stop_ebpf_program(struct eunomia_bpf *prog)
{
    if (!prog) {
        return;
    }
    prog->program.destroy();
}
/// @brief free the memory of the program
void
free_bpf_skel(struct eunomia_bpf *prog)
{
    if (!prog) {
        return;
    }
    delete prog;
}

int
get_bpf_fd(struct eunomia_bpf *prog, const char *name)
{
    if (!prog) {
        return -1;
    }
    return prog->program.get_fd(name);
}
}