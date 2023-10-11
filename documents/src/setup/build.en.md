---
title: build from source
catagories: ['installation']
---

# build eunomia-bpf project

If you want to run the cli, in most cases, you don't need to build your own.

## Install Dependencies

You will need `clang`, `libelf` and `zlib` to build the examples, package names may vary across distros.

On Ubuntu/Debian, you need:

```shell
apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:

```shell
dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

install rust toolchain

```shell
curl https://sh.rustup.rs -sSf | sh -s
```

## build bpf-loader-rs

bpf-loader is our core library written in C++17. It has no other dependencies except libbpf.

```shell
make bpf-loader-rs # build ebpf-loader-rs
```

The recommended compiler is gcc9 or later.

## build ecli

After compile the bpf-loader, you can build the cli tool in C++:

```shell
make ecli
```

reference: <https://github.com/libbpf/libbpf-bootstrap>

## build wasm lib

```shell
make wasm-runtime
```

Please install WASI SDK, download the [wasi-sdk](https://github.com/CraneStation/wasi-sdk/releases) release and extract the archive to default path /opt/wasi-sdk if you want to compile c code to wasm.

## build compiler

```shell
make ecc
```

# install from package manager

## nix

On any distros with nix installed:

### build ecc

```shell
nix build github:eunomia-bpf/eunomia-bpf#ecc # or ecli, see `nix flake show` for details # or ecli
```

Run application directly with:

```shell
nix run github:eunomia-bpf/eunomia-bpf#ecc -- -h
```

## openEuler

```shell
sudo dnf search eunomia-bpf
# and install
```


## more details

- You can check the Makefile at project root for more details: [Makefile](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/compiler/Makefile)
- You may want to refer to our CI for more build info: [ecc.yml](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/.github/workflows/ecc-binary.yml)
