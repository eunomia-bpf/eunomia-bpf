# ecli - eunomia-bpf CLI

`ecli` is the local CLI for loading, running, pulling, and pushing eunomia-bpf programs.

The legacy remote HTTP mode (`ecli client` / `ecli-server`) has been removed from the main branch to reduce maintenance overhead. The last implementation is preserved on the `archive/ecli-remote-http` branch.

## Components

The ecli workspace now consists of two crates:

### 1. `ecli-lib`

Core library providing:
- local program execution through `bpf-loader-lib`
- OCI registry push/pull helpers
- URL and file loading helpers

### 2. `client` / `ecli`

CLI wrapper around `ecli-lib`, exposing:
- `run`
- `push`
- `pull`

## Install

```bash
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli -O ecli
chmod +x ./ecli
```

Or build from source:

```bash
cd ecli
cargo build --release -p client
cp target/release/ecli-rs ./ecli
```

## Run Programs

Run a local package:

```bash
sudo ./ecli run ../examples/bpftools/bootstrap/package.json
```

Run from an OCI registry:

```bash
sudo ./ecli run ghcr.io/eunomia-bpf/execve:latest
```

Run from a URL:

```bash
sudo ./ecli run https://example.com/program.json
```

## OCI Operations

Pull an image:

```bash
./ecli pull ghcr.io/eunomia-bpf/execve:latest
```

Push a Wasm module with credentials loaded from Docker config when available:

```bash
./ecli push --module app.wasm ghcr.io/yourorg/mytool:v1.0
```

Prompt for registry credentials:

```bash
./ecli push --module app.wasm -i ghcr.io/yourorg/mytool:v1.0
```

Provide credentials inline:

```bash
./ecli push --module app.wasm -u USER -p TOKEN ghcr.io/yourorg/mytool:v1.0
```

## Help

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
