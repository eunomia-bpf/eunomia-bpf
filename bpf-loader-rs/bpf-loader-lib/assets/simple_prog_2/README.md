# simple_prog_2

Here is a program which will be used to test the section loader.

Note: This files will only be used to test the loader, and the data will only be loaded into a local buffer, not one the ebpf program holds.

- `simple_prog_2.c`: A C file contains several variable declarations. Tests about section loader will try to fill the variable with an initial value, and check the filling result
- `simple_prog_2.bpf.o`: The BPF ELF file compiled from `simple_prog_2.c`
- `simple_prog_2.package.json`: The JSON skeleton of `simple_prog_2.bpf.o`, with ELF binary inside
- `simple_prog_2.skel.json`: The JSON skeleton, without ELF binary
