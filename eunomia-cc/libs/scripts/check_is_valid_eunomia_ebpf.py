# check if it can be run with ecli
import os
import json

# check a single BPF_MAP_TYPE_RINGBUF with a single RING_BUFFER_EXPORT
output_dir = "./.output/"
ebpf_program_data = os.path.join(output_dir, "ebpf_program.json")
ring_buffer_layout_data = os.path.join(output_dir, "event_layout.json")

global_data = {}
# load global config data
with open(ebpf_program_data) as f:
    global_data = json.load(f)

with open(ring_buffer_layout_data) as f:
    ring_buffer_data = json.load(f)
    maps_data = global_data["maps"]
    ring_buffer_count = 0
    for map in maps_data:
        if map["type"] == "BPF_MAP_TYPE_RINGBUF" or map["type"] == "BPF_MAP_TYPE_PERF_EVENT_ARRAY":
            ring_buffer_count = ring_buffer_count + 1

    if ring_buffer_count > 1:
        print()("ERROR: we only support one RING_BUFFER")
        exit(1)

    if ring_buffer_count == 1:
        if len(ring_buffer_data) != 1:
            print("WARN: YOU have multiple RING_BUFFER_EXPORT structs in bpf.h. The first will be used as a export type.")

    if ring_buffer_count == 0:
        # it's OK to do so
        pass
