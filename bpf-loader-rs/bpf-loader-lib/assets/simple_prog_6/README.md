# simple_prog_6

Here is a program which will be used to test the attaching and detaching of tc.

- `test.bpf.c`: The C code of a BPF program using tc
- `test.bpf.o`: The BPF ELF file compiled from `test.bpf.c`
- `package.json`: The JSON skeleton of `test.bpf.o`, with ELF binary inside
- `test.skel.json`: The JSON skeleton, without ELF binary