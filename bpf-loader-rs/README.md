# bpf-loader-rs

Here is the project root of `bpf-loader` rewritten in Rust, called `bpf-loader-rs`.

- `bpf-loader-lib`: The core library implemention of `bpf-loader-rs`
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
