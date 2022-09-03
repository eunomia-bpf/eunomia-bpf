# build

If you want to run the cli, in most cases, you don't need to build your own.

## common problems

if you get a error

sudo apt-get upgrade libstdc++6


# Building

libbpf-bootstrap supports multiple build systems that do the same thing.
This serves as a cross reference for folks coming from different backgrounds.

## Install Dependencies

You will need `clang`, `libelf` and `zlib` to build the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

## build

```shell
$ git submodule update --init --recursive       # check out libbpf
$ make eunomia-bpf                              # build eunomia-bpf
```

build ecli:


reference: https://github.com/libbpf/libbpf-bootstrap
