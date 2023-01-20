# ewasm: a dynamically loading library for eBPF with WASM

- build the user space and kernel space eBPF as a WASM module
- load the WASM module dynamically and run with bpf-loader

## How it works

The library use the `bpf-loader` library to load `eBPF` program from a `WASM` module, you can write a WASM module to operate the eBPF program or process the data in user space `WASM` runtime. The idea is simple:

1. compile the kernel eBPF code skeleton to the `JSON` format with `eunomia-cc` toolchain
2. embed the `JSON` data in the `WASM` module, and provide some API for operating the eBPF program skeleton
3. load the `JSON` data from the `WASM` module and run the eBPF program skeleton with `bpf-loader` library

## example: opensnoop

- [test/wasm-apps/opensnoop.c](test/wasm-apps/opensnoop.c)

The API demo:

```c
#include "opensnoop.h"

int
bpf_main(char *env_json, int str_len)
{
    int res = create_bpf(program_data, strlen(program_data));
    if (res < 0) {
        printf("create_bpf failed %d", res);
        return -1;
    }
    res = run_bpf(res);
    if (res < 0) {
        printf("run_bpf failed %d\n", res);
        return -1;
    }
    res = wait_and_poll_bpf(res);
    if (res < 0) {
        printf("wait_and_poll_bpf failed %d\n", res);
        return -1;
    }
    return 0;
}

int
process_event(int ctx, char *e, int str_len)
{
    printf("%s\n", e);
    return -1;
}
```

For the kernel code, please refer to [../examples/bpftools/opensnoop](../examples/bpftools/opensnoop).

### build the WASM module. 
```console
$ make /opt/wasi-sdk    # install WASI SDK
$ cd ./test/wasm-apps/ && make && cd -
```

> To install the latest WASI SDK, you can download the latest [wasi-sdk](https://github.com/CraneStation/wasi-sdk/releases) release and extract the archive to default path `/opt/wasi-sdk`.

You will get a `opensnoop.wasm` file in folder `test\wasm-apps`, which contains the pre-compiled kernel eBPF code and user-space `WASM` code.

### run eBPF from WASM module

```console
$ cd wasm-runtime
$ mkdir build && cd build
$ cmake -Dewasm_BUILD_EXECUTABLE=ON -DCMAKE_BUILD_TYPE=Release .. && make	# generate ewasm loader
$ sudo ./bin/Release/ewasm ../test/wasm-apps/opensnoop.wasm

{"pid":1509,"uid":0,"ret":11,"flags":0,"comm":"YDService","fname":"/proc/self/stat"}
{"pid":1509,"uid":0,"ret":3,"flags":0,"comm":"YDService","fname":"/home/ubuntu/.zsh_history"}
{"pid":1509,"uid":0,"ret":3,"flags":0,"comm":"YDService","fname":"/proc/565169/cmdline"}
{"pid":1509,"uid":0,"ret":3,"flags":0,"comm":"YDService","fname":"/proc/565170/cmdline"}
```

## compile

```sh
make build
```
