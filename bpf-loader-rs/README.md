# bpf-loader-rs

Here is the project root of `bpf-loader` rewritten in Rust, called `bpf-loader-rs`.

- `bpf-loader-lib`: The core library implementation of `bpf-loader-rs`
- `bpf-loader-cli`: A CLI which can be used to run skeletons, commandline arguments generating is also supported
- `bpf-loader-c-wrapper`: The C library of `bpf-loader`. It exports the same interface like the previous C++ one.

## Build

Run `cargo run` under the root directory will build and run `bpf-loader-cli`, which is a command line skeleton runner.

Run `cargo build` will build all the things, including `bpf-loader-c-wrapper`. 

The compiled static or shared objects can be found at `target/debug/libeunomia.a` and `target/debug/libeunomia.so`. 

If you run `cargo build` with `--release` argument, a release version will be built, which has smaller size and faster running speed. They can be found at `target/release/libeunomia.a` and `target/release/libeunomia.so`

## Run

Some example programs are provides, they are:
- `bpf-loader-lib/assets/bootstrap.json`
- `bpf-loader-lib/assets/runqlat.json`

You can run `cargo run -- <PATH>`, with `<PATH>` replaced with one of the above ones, to see the output.

For example, this is a piece of output from the bootstrap.

```console
$ cargo run -- bpf-loader-lib/assets/bootstrap.json 
INFO [faerie::elf] strtab: 0xa2bf symtab 0xa2f8 relocs 0xa340 sh_offset 0xa340
TIME     PID    PPID   EXIT_CODE DURATION_NS COMM   FILENAME EXIT_EVENT ET     
INFO [bpf_loader_lib::skeleton::poller] Running ebpf program...
16:58:31  506334 486903 0        0           "sh"   "/bin/sh" false     "EVENT_TYPE__ENTER(0)"
16:58:31  506335 506334 0        0           "which" "/usr/bin/which" false "EVENT_TYPE__ENTER(0)"
16:58:31  506335 506334 0        754015      "which" ""      true       "EVENT_TYPE__ENTER(0)"
16:58:31  506334 486903 0        1903616     "sh"   ""       true       "EVENT_TYPE__ENTER(0)"
16:58:31  506336 486903 0        0           "sh"   "/bin/sh" false     
```

If you want to disable the annoying `INFO XXX` lines, you can add `--no-log` argument to the CLI program, see:

```console
$ cargo run -- --no-log bpf-loader-lib/assets/bootstrap.json 
TIME     PID    PPID   EXIT_CODE DURATION_NS COMM   FILENAME EXIT_EVENT ET     
17:01:23  506672 486903 0        0           "sh"   "/bin/sh" false     "EVENT_TYPE__ENTER(0)"
17:01:23  506673 506672 0        0           "which" "/usr/bin/which" false "EVENT_TYPE__ENTER(0)"
17:01:23  506673 506672 0        1305209     "which" ""      true       "EVENT_TYPE__ENTER(0)"
17:01:23  506672 486903 0        3746888     "sh"   ""       true       "EVENT_TYPE__ENTER(0)"
17:01:23  506674 486903 0        0           "sh"   "/bin/sh" false     "EVENT_TYPE__ENTER(0)"
17:01:23  506675 506674 0        0           "ps"   "/usr/bin/ps" false "EVENT_TYPE__ENTER(0)"
```

## The Skeleton (with multiple export type support)

- If `enable_multiple_export_types` in `EunomiaObjectMeta` is set to `true`, then multiple export types will be supported. Otherwise the behavior is compatible to the old version

The `export_types` field will be ignored if multiple export types is enabled.

There will be a field `export_config` under the `MapMeta` of each map, it can be either of the four variants:

- String `"no_export"`. indicating that this map is not used for exporting
- String `"default"`. Only applies to sample maps. indicating that this map is used for exporting, and the export struct type will be read from BTF and the map's `btf_value_type_if`
- Object `{"btf_type_id": <u32>}`. Applies to all maps. Indicate that use this btf type as the map's export type. For ringbuf or perfevent, it will be used to interpret the data that kernel programs send. For sample maps, it will be used to interpret the value of maps
- Object `{"custom_members" : [{"name": <String>, "offset": <usize>, "btf_type_id": <u32>}]}`. Applies to all maps. Indicates that the map will export a struct containing the described members. `name` is the name of the field. `offset` is its offset. `btf_type_id` is the type id of the field.
