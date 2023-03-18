### Usage
```sh
ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]
```
  
Compiles and generates a bpf object from the provided SOURCE_PATH path for the specified eBPF program.

### example
```sh
ecc -b client.bpf.c event.h
```
This command will compile client.bpf.c and event.h into client.bpf.o,
and package them as json, export a tar containing a custom btf file.

output in `OUTPUT_PATH`:
```sh
package.json
client.tar #include custom btf files
```

#### Arguments

- `SOURCE_PATH`: path of the bpf.c file to compile

- `EXPORT_EVENT_HEADER`: path of the bpf.h header for defining event struct


#### Options

- -o, --output-path `OUTPUT_PATH`: path of output bpf object

- -w, --workspace-path `WORKSPACE_PATH`: specify custom workspace path 

- -a, --additional-cflags `ADDITIONAL_CFLAGS`: additional cflags for clang
  - example `-a="-fstack-protector"`,
  this avoids runtime errors on some distributions that have clang stack protection enabled by default.

- -c, --clang-bin `CLANG_BIN`: path of clang binary (default: clang)

- -l, --llvm-strip-bin `LLVM_STRIP_BIN`: path of llvm-strip binary (default: llvm-strip)

- -s, --subskeleton: do not pack bpf object in config file

- -v, --verbose: print the command execution

- -y, --yaml: output config skel file in yaml

- --header-only: generate a bpf object for struct definition in header file only

- --wasm-header: generate wasm include header

- -b, --btfgen: fetch custom btfhub archive file and package into tar
  - If `BTFHUB_ARCHIVE` does not exist, it will clone
  [btfhub](https://github.com/aquasecurity/btfhub-archive) to `BTFHUB_ARCHIVE`.
  - This option will take a lot of time, if you don't want to package or generate all custom btf files,
  you can keep only the required btf files in `BTFHUB_ARCHIVE`.
  - Don't worry, even the tar containing all the btfhub archives is only `5-10MB` in size.

- --btfhub-archive `BTFHUB_ARCHIVE`: directory to save btfhub archive file (default:`$HOME/.eunomia/btfhub-archive`)

- -h, --help: prints help documentation.

- -V, --version: prints version information.
