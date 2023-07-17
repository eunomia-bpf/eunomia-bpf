# The new `ecli`

Here is the brand new ecli.

There are four crates:
- `ecli-lib`: Core implementation, which implements OCI-registry operations, ecli-http-server, ecli-http-client, and ecli-native-runner. It also has several features to control the behavior. See below.
- `client`: The client wrapper. It wraps the `ecli-http-client` and `ecli-native-client` from the `ecli-lib`, and can be enabled separately by features
- `server`: The server wrapper. It wraps the `ecli-http-server`, and can be directly started to host a HTTP server. The api definitions can be found at `apis.yaml`
- `server-codegen`: The generated code from `apis.yaml`, containing a server implementation and client implementation. `ecli-lib` implements the underlying service thtough this

## `client` / `ecli`

There are a few interesting features:
- `http`: Default. Let the client be able to run ebpf program (both json and wasm) on a remote machine, through the HTTP API. 
- `native`: Default. Let the client be able to run ebpf program at the local machine.

Note: If you only enable the `http` feature, `ecli` can even run on Windows!

- If you want to build a `remote-only` client, just run `cargo build --no-default-features --features http` in the `client` folder.
## `ecli-lib`

Some features can be used to control the behavior, they are:

- `native-client`: Let `ecli-lib` support running programs at the local machine. This feature will enable the dependency of `bpf-loader-lib` and `wasm-bpf-rs`
- `http-client`: Let `ecli-lib` support running program at a remote machine, through `ecli server api`.
- `http-server`: Let `ecli-lib` provide ecli server API implementations. This also enables `native-client`

## `server` / `ecli-server`

It will serve a http service once it was started, and will accept calls defined by `apis.yaml`, and run ebpf programs on the machine where it runs.

Currently no authorization is implemented, maybe you will need an authorization gateway.

## Another noticeable place - the log tracking

The server holds a log buffer - every pieces of logs that a program produced (stderr/stdout of the wasm program, or callback-produced values of a json program) will be cached before we get it from the client.

Each piece of log has a `timestamp`, indicates the order that the piece of log was generated.

When fetching logs through the HTTP API, we also need to provide a `cursor`, to tell the server `we only need logs greater or equal than this timestamp`. The server will give us the logs begins with the provided `cursor`, and drops the logs before the cursor (We don't need them anymore).


# Examples

## Pull an image from a registry

```bash
ecli pull https://ghcr.io/eunomia-bpf/sigsnoop:latest
```

## Push an image to a registry

```bash
ecli push https://ghcr.io/eunomia-bpf/sigsnoop:latest
ecli push https://yunwei37:[password]@ghcr.io/eunomia-bpf/sigsnoop:latest
```

## Run a program natively:
- Requires feature `native`
```console
$ sudo ./ecli run examples/bpftools/bootstrap/package.json
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    FILENAME  EXIT_EVENT  
22:01:04  46310  2915    0          0            sh      /bin/sh   0
22:01:04  46311  46310   0          0            which   /usr/bin/which 0
22:01:04  46311  46310   0          2823776      which             1
22:01:04  46310  2915    0          6288891      sh                1
22:01:04  46312  2915    0          0            sh      /bin/sh   0
22:01:04  46313  46312   0          0            ps      /usr/bin/ps 0
```

## Run a program remotely
- Requires feature `http`
```console
$ ecli client  --endpoint http://127.0.0.1:8527 start ./ecli-lib/tests/bootstrap.wasm 
1
```
It prints the handle of the just-started program.
## Track logs of a remote program
- Requires feature `http`
```console
$ ecli client  --endpoint http://127.0.0.1:8527 log 1 --follow
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
16:03:16 EXEC  sh               51857   1711    /bin/sh
16:03:16 EXEC  which            51858   51857   /usr/bin/which
16:03:16 EXIT  which            51858   51857   [0] (0ms)
16:03:16 EXIT  sh               51857   1711    [0] (1ms)
16:03:16 EXEC  sh               51859   1711    /bin/sh
16:03:16 EXEC  ps               51860   51859   /usr/bin/ps
16:03:16 EXIT  ps               51860   51859   [0] (17ms)
```

With the `--follow` argument, ecli will keeping tracking the logs of the remote program until `ecli` was killed or the remote program was killed.
