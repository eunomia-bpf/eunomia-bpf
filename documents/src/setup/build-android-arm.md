---
title: build on android aarch64
catagories: ['installation']
---

# Build on Android

Android上build需要先Installing Debian on Android in Termux

在Android上构建时，需要先Installing Debian on Android in Termux

1. install termux

    <https://github.com/termux/termux-app/releases/tag/v0.118.0>

2. install proot-distro

    select debian distro

    ```sh
    pkg install proot-distro
    proot-distro install debian
    proot-distro login debian
    ```

3. install packages

    remember `proot-distro login debian` first

    ```sh
    apk update
    apt install clang cmake libelf1 libelf-dev zlib1g-dev
    ```

    之后的步骤和在ARM上build上相同

## Build on ARM

1. 同步 eunomia-bpf 到本地

    ```sh
    git clone https://github.com/eunomia-bpf/eunomia-bpf.git
    cd eunomia-bpf
    git submodule update --init --recursive --remote
    ```

2. 配置环境变量

    ```sh
    export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
    ```

3. 安装依赖

    ```sh
    apt update
    apt install clang cmake libelf1 libelf-dev zlib1g-dev
    ```

4. 修改wasm-runtime/CMakeLists.txt` 中的 `WAMR_BUILD_TARGET（may not required）

    change `set (WAMR_BUILD_TARGET "X86_64")` to `set (WAMR_BUILD_TARGET "AARCH64")`

5. 编译

    ```sh
    make bpf-loader
    make ecli
    ```

6. 检查输出

    ```sh
    root@localhost:~/eunomia-bpf# file ecli/build/bin/Release/ecli
    ecli: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=eab42b79be75951e3a573aa7c61136239d35c868, for GNU/Linux 3.7.0, with debug_info, not stripped
    ```