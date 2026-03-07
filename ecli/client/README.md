# `ecli`

The `client` crate builds the local `ecli` binary.

The legacy remote HTTP mode has been removed from the main branch. The last implementation is preserved on the `archive/ecli-remote-http` branch.

## Run a program

```console
$ sudo ./ecli run ./ecli-lib/tests/bootstrap.wasm
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
16:24:34 EXIT  sleep            53566   53561   [0]
16:24:34 EXEC  sed              53567   53561   /usr/bin/sed
16:24:34 EXIT  sed              53567   53561   [0] (1ms)
16:24:34 EXEC  cat              53568   53561   /usr/bin/cat
16:24:34 EXIT  cat              53568   53561   [0] (0ms)
16:24:34 EXIT  cpuUsage.sh      53569   53561   [0]
```

## Usage

```console
$ ./ecli -h
ecli subcommands, including run, push, pull

Usage: ecli [COMMAND_LINE]... [COMMAND]

Commands:
  run     run ebpf program
  push    Operations about pushing image to registry
  pull    Operations about pulling image from registry
  help    Print this message or the help of the given subcommand(s)
```
