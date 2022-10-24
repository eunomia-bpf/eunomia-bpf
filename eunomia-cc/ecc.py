#!/bin/python
# the loader of eunomia-cc compile toolchain
import os
import argparse

# use to replace the build starter in make
# provide args to access

# 	$(Q)make compile
# 	$(Q)cp -f .output/package.json $(SOURCE_OUTPUT_PACKAGE_FILE)


def create_args():
    parser = argparse.ArgumentParser(
        description="eunomia-cc compile toolchain")
    parser.add_argument('file', type=str, default='*.bpf.c',
                        help='the ebpf source file in the dir to compile')
    parser.add_argument('-d', '--dir', default='../',
                        help='the dir to compile')
    parser.add_argument(
        '-o', '--output', default='package.json', help='the output file name')
    parser.add_argument('-i', '--includes', default="../",
                        help='include headers path')
    args= parser.parse_args()
    head, tail = os.path.split(args.file)
    if os.path.split(args.file):
        if tail != args.file:
            args.dir = head
    return args

def main():
    args = create_args()

    # the input path
    output_path = os.path.join(args.dir, args.output)
    input_export_define_header = os.path.join(args.includes, "*.bpf.h")
    input_config_file = os.path.join(args.dir, "config.json")

    # the compile path
    compile_file_path = "./client.bpf.c"
    current_dir_path = "./"
    compile_export_define_header_path = "./event.h"
    compile_config_file_path = "./config.json"
    compile_output_path = ".output/package.json"

    os.system("make clean_cache")
    res = os.system("cp -f " + args.file + " " + compile_file_path)
    if res != 0:
        print("cannot read the source *.bpf.c file!")
        exit(1)
    os.system("cp -f " + input_export_define_header + " " +
              current_dir_path + " 2>/dev/null")
    os.system("cp -f " + input_export_define_header + " " +
              compile_export_define_header_path + " 2>/dev/null")
    os.system("cp -f " + input_config_file + " " +
              compile_config_file_path + " 2>/dev/null")
    res = os.system("make compile")
    if res != 0:
        print("compile failed!")
        exit(1)
    os.system("cp -f " + compile_output_path + " " + output_path)


if __name__ == '__main__':
    main()
