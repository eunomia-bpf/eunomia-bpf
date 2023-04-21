# ecli: run ebpf programs as json or wasm

## Usage

```sh
sudo ecli <COMMAND>
```

## example

Run the ebpf program as wasm or json.

```sh
# run with wasm bpf modules
sudo ecli run runqlat.wasm
# run with json bpf object only
sudo ecli run package.json
```

Or run the ebpf program as a tar file contains minimal BTF info and bpf object.

```sh
sudo ecli run client.tar
```

The ecc packaged tar contains custom btf files and `package.json`, which can be run on older kernels.

For details, see [ecc-btfgen](../ecc/usage.md#options)

## Commands

- run - Run the ebpf program as tar or json.
- push - Push a container to an OCI registry.
- pull - Pull a container from an OCI registry.
- login - Login to an OCI registry.
    `ecli` will check [gh](https://cli.github.com/) cache and `GITHUB_TOKEN`
    env when you login to ghcr.io, either one can be logged into ghcr without entering a token.
- logout - Logout from an OCI registry.
    `ecli logout xxx` will remove identity certificates stored under `~/.eunomia`.
