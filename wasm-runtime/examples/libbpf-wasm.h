#ifndef _LIBBPF_WASM_H
#define _LIBBPF_WASM_H


#include <errno.h>
#include <stdlib.h>

struct bpf_map {
	char name[64];
};

struct bpf_program {
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
	struct bpf_link **link;
};

struct bpf_object_skeleton {
	size_t sz; /* size of this struct, for forward/backward compatibility */
	const char *name;
	const void *data;
	size_t data_sz;

	struct bpf_object **obj;

	int map_cnt;
	int map_skel_sz; /* sizeof(struct bpf_map_skeleton) */
	struct bpf_map_skeleton *maps;

	int prog_cnt;
	int prog_skel_sz; /* sizeof(struct bpf_prog_skeleton) */
	struct bpf_prog_skeleton *progs;
};

static int bpf_map__fd(const struct bpf_map *map) {
	
}

#endif // _LIBBPF_WASM_H
