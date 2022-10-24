# fix the types in ebpf source code
import re
import os
import json

source_file_path = 'client.bpf.c'

regex = r'struct\s*\{.*?__uint\(type, (BPF_MAP_TYPE_.*?)\);.*?\}\s+(\w+)\s+SEC\(".maps"\);'
source = ""
with open(source_file_path) as f:
    source = f.read()

# add the find types to the source code
find = re.findall(regex, source, re.DOTALL)
type_dict = {}
for i in find:
    type_dict[i[1]] = i[0]
    # print(i[0], i[1])

output_dir = ".output"
ebpf_program_data_path = os.path.join(output_dir, "ebpf_program_without_type.json")

with open(ebpf_program_data_path) as f:
    ebpf_data=json.load(f)
    for map in ebpf_data["maps"]:
        if map["name"] in type_dict:
            map["type"]=type_dict[map["name"]]
        else:
            map["type"]="BPF_MAP_TYPE_UNSPEC"   # we cannot get type info from source
    print(json.dumps(ebpf_data, indent=4))
