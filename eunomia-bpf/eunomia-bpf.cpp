/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙
 * All rights reserved.
 */
#include "eunomia-bpf.h"

#include "event.h"
#include "json.hpp"
#include "base64.h"
#include <iostream>

extern "C"
{
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <stdio.h>
}

using json = nlohmann::json;
static int create_prog_skeleton_from_json(
	struct eunomia_ebpf_program &ebpf_program);

std::string bpf_skeleton_encode_json(const struct bpf_object_skeleton *skeleton)
{
	struct eunomia_ebpf_meta_data data;

	data.ebpf_name == skeleton->name;
	data.data_sz = skeleton->data_sz;
	data.ebpf_data = base64_encode((const unsigned char *)skeleton->data, data.data_sz);
	for (int i = 0; i < skeleton->map_cnt; i++)
	{
		data.maps_names.push_back(skeleton->maps[i].name);
	}
	for (int i = 0; i < skeleton->prog_cnt; i++)
	{
		data.progs_names.push_back(skeleton->progs[i].name);
	}
	return data.to_json_str();
}

std::string eunomia_ebpf_meta_data::to_json_str()
{
	json j;
	j["name"] = ebpf_name;
	j["maps"] = maps_names;
	j["progs"] = progs_names;
	j["data_sz"] = data_sz;
	j["data"] = ebpf_data;
	return j.dump();
}

void eunomia_ebpf_meta_data::from_json_str(const std::string &j_str)
{
	json jj = json::parse(j_str);
	ebpf_name = jj["name"];
	maps_names = jj["maps"];
	progs_names = jj["progs"];
	data_sz = jj["data_sz"];
	ebpf_data = jj["data"];
}

static int handle_print_event(void *ctx, void *data, size_t data_sz);

int open_ebpf_program_from_json(struct eunomia_ebpf_program &ebpf_prog, const std::string &json_str)
{
	ebpf_prog.meta_data.from_json_str(json_str);
	return 0;
}

int run_ebpf_program(struct eunomia_ebpf_program &ebpf_program)
{
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	if (create_prog_skeleton_from_json(ebpf_program))
	{
		std::cerr << "Failed to create skeleton from json" << std::endl;
		return 1;
	}
	if (bpf_object__open_skeleton(ebpf_program.skeleton, NULL))
	{
		std::cerr << "Failed to open skeleton" << std::endl;
		return 1;
	}

	/* Load & verify BPF programs */
	err = bpf_object__load_skeleton(ebpf_program.skeleton);
	if (err)
	{
		std::cerr << "Failed to load skeleton" << std::endl;
		return 1;
	}

	/* Attach tracepoints */
	err = bpf_object__attach_skeleton(ebpf_program.skeleton);
	if (err)
	{
		std::cerr << "Failed to attach skeleton" << std::endl;
		return 1;
	}
	/* Set up ring buffer polling */
	// FIXME: rb must be 0 for now
	ebpf_program.rb = ring_buffer__new(bpf_map__fd(ebpf_program.maps[0]), handle_print_event, NULL, NULL);
	if (!ebpf_program.rb)
	{
		fprintf(stderr, "Failed to create ring buffer\n");
		return 0;
	}

	/* Process events */
	while (!ebpf_program.exiting)
	{
		err = ring_buffer__poll(ebpf_program.rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}
	return 0;
}

void stop_ebpf_program(const struct eunomia_ebpf_program &ebpf_program)
{
	if (ebpf_program.skeleton)
		bpf_object__destroy_skeleton(ebpf_program.skeleton);
	if (ebpf_program.rb)
		ring_buffer__free(ebpf_program.rb);
}

static int create_prog_skeleton_from_json(
	struct eunomia_ebpf_program &ebpf_program)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		return -1;

	s->sz = sizeof(*s);
	s->name = ebpf_program.meta_data.ebpf_name.c_str();

	/* maps */
	s->map_cnt = ebpf_program.meta_data.maps_names.size();
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps)
		goto err;

	ebpf_program.maps.resize(s->map_cnt);
	for (int i = 0; i < s->map_cnt; i++)
	{
		s->maps[i].name = ebpf_program.meta_data.maps_names[i].c_str();
		s->maps[i].map = &ebpf_program.maps[i];
	}

	/* programs */
	s->prog_cnt = ebpf_program.meta_data.progs_names.size();
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;
	ebpf_program.progs.resize(s->prog_cnt);
	ebpf_program.links.resize(s->prog_cnt);
	for (int i = 0; i < s->prog_cnt; i++)
	{
		s->progs[i].name = ebpf_program.meta_data.progs_names[i].c_str();
		s->progs[i].prog = &ebpf_program.progs[i];
		s->progs[i].link = &ebpf_program.links[i];
	}

	s->data_sz = ebpf_program.meta_data.data_sz;
	ebpf_program.base64_decode_buffer = base64_decode((const unsigned char *)ebpf_program.meta_data.ebpf_data.c_str(), ebpf_program.meta_data.ebpf_data.size());
	s->data = (void *)ebpf_program.base64_decode_buffer.data();

	s->obj = &ebpf_program.obj;
	ebpf_program.skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return -1;
}

static int handle_print_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = (const struct event *)data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-7d %-7d %s %s %d %u %u %lld %lld\n",
		   ts, e->pid, e->ppid, e->char_buffer16, e->char_buffer127, e->bool_value1,
		   e->u32_value1, e->u32_value2, e->u64_value1, e->u64_value2);
	return 0;
}
