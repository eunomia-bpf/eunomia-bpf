# a simple demo for ewasm

## build

```bash
mkdir build && cd build
cmake ..
make
```

## run

```console
$ build/demo
usage: ./build/ewasm_demo <json config file>

sudo ./build/ewasm_demo ../../wasm-runtime/test/wasm-apps/opensnoop.wasm 
{"ts":0,"pid":153,"uid":0,"ret":5,"flags":32768,"comm":"init","fname":"/proc/net/tcp"}
{"ts":0,"pid":153,"uid":0,"ret":5,"flags":32768,"comm":"init","fname":"/proc/net/tcp6"}
{"ts":0,"pid":153,"uid":0,"ret":5,"flags":32768,"comm":"init","fname":"/proc/net/tcp"}
{"ts":0,"pid":153,"uid":0,"ret":5,"flags":32768,"comm":"init","fname":"/proc/net/tcp6"}
```