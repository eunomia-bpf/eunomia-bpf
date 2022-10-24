# add ringbuffer event type definition to json
import re
import json
import sys

event_layout_output_path = ".output/event_layout.txt"
output_event_c_path = ".output/rb_export_event.c"
event_header_path = "event.h"

def get_struct_memory_layout(f):
    json_data = {}
    json_data['Fields'] = []
    line_num = 2
    while True:
        line = f.readline()
        line_num = line_num + 1
        # print(line_num, line)
        if not line:
            break
        if line == "":
            continue
        if line_num == 3:  # Type: struct event
            find = re.search(r"Type: struct (.*)$", line)
            if not find:
                print("Error: line 3 struct")
                break
            # print("Struct Name: ", find.group(1))
            json_data['Struct Name'] = find.group(1)
        elif line_num == 6:  # Size:1472
            find = re.search(r"Size:(\d*)$", line)
            if not find:
                print("Error: line 6 Size")
                break
            # print("Size: ", find.group(1))
            json_data['Size'] = int(find.group(1))
        elif line_num == 7:  # DataSize:1472
            find = re.search(r"DataSize:(\d*)$", line)
            if not find:
                print("Error: line 7 DataSize")
                break
            # print("DataSize: ", find.group(1))
            json_data['DataSize'] = int(find.group(1))
        elif line_num == 8:  # Alignment:64
            find = re.search(r"Alignment:(\d*)$", line)
            if not find:
                print("Error: line 8 Alignment")
                break
            # print("Alignment: ", find.group(1))
            json_data['Alignment'] = int(find.group(1))
        # FieldOffsets: [0, 32, 64, 96, 128, 192, 256, 384, 1408]
        elif line_num == 9:
            find = re.search(r"FieldOffsets: (.*)>", line)
            if not find:
                print("Error: line 9 FieldOffsets")
                break
            # print("FieldOffsets: ", find.group(1))
            json_data['FieldOffsets'] = json.loads(find.group(1))
        #   LLVMType:%struct.event = type { i32, i32, i32, i32, i64, i64, [16 x i8], [127 x i8], i32 }
        elif line.startswith("  LLVMType"):
            find = re.search(r"  LLVMType:.* = type \{ (.*) \}", line)
            if not find:
                print("Error: LLVMType")
                break
            # print("LLVMType: ", find.group(1))
            LLVMType = find.group(1).split(', ')
            json_data['LLVMType'] = LLVMType
        elif line.startswith("*** Dumping AST Record Layout"):
            break
        # FieldDecl 0x1af20c8 <line:12:2, col:6> col:6 pid 'int'
        else:
            find = re.search(r"FieldDecl .* <.*> col:\d+ (.*) '(.*)'", line)
            if not find:
                continue
            # print("FieldDecl: ", find.group(1), find.group(2))
            field_data = {}
            field_data['Name'], field_data['Type'] = find.group(
                1), find.group(2)
            json_data['Fields'].append(field_data)
    # skip No export data
    if json_data == {"Fields": []}:
        return None

    # merge the types of LLVMType, FieldOffset and FieldDecl
    assert(len(json_data['Fields']) == len(json_data['LLVMType']))
    assert(len(json_data['Fields']) == len(json_data['FieldOffsets']))
    for i in range(len(json_data['Fields'])):
        json_data['Fields'][i]['LLVMType'] = json_data['LLVMType'][i]
        json_data['Fields'][i]['FieldOffset'] = json_data['FieldOffsets'][i]
    json_data.pop('LLVMType')
    json_data.pop('FieldOffsets')
    return json_data

# get the mem layout output of clang to json
def get_event_mem_layout_json():
    all_data = []
    with open(event_layout_output_path) as f:
        line = f.readline()
        line = f.readline()
        while True:
            data = get_struct_memory_layout(f)
            if (data == None):
                break
            all_data.append(data)

    print(json.dumps(all_data, indent=4))

# add the use of event.c so we can generate mem layout correctly
def fix_use_of_rb_event():
    c_generate_prefix = """
    // do not use this file: auto generated
    #include <stddef.h>
    #include <stdint.h>
    #include <stdbool.h>
    #include "asm-generic/int-ll64.h"
    #include "../event.h"

    // make the compile not ignore event struct
    """
    event_header_content = ""
    with open(event_header_path) as f:
        event_header_content = f.read()

    with open(output_event_c_path, "w") as f:
        finds = re.findall("(struct\s+(\w+))", event_header_content)
        # print(finds)
        for find in finds:
            c_generate_prefix = c_generate_prefix + find[0] + "* " + find[1] + " = NULL;"
        f.write(c_generate_prefix)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        fix_use_of_rb_event()
    else:
        get_event_mem_layout_json()