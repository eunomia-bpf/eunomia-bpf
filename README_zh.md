![logo](documents/src/img/logo.png)

# eunomia-bpf：简化并增强eBPF，支持CO-RE[^1]和WebAssembly[^2]

[![Actions Status](https://github.com/eunomia-bpf/eunomia-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/eunomia-bpf/actions)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/eunomia-bpf/eunomia-bpf)](https://github.com/eunomia-bpf/eunomia-bpf/releases)
[![codecov](https://codecov.io/gh/eunomia-bpf/eunomia-bpf/branch/master/graph/badge.svg?token=YTR1M16I70)](https://codecov.io/gh/eunomia-bpf/eunomia-bpf)
[![DeepSource](https://deepsource.io/gh/eunomia-bpf/eunomia-bpf.svg/?label=active+issues&show_trend=true&token=rcSI3J1-gpwLIgZWtKZC-N6C)](https://deepsource.io/gh/eunomia-bpf/eunomia-bpf/?ref=repository-badge)
[![CodeFactor](https://www.codefactor.io/repository/github/eunomia-bpf/eunomia-bpf/badge)](https://www.codefactor.io/repository/github/eunomia-bpf/eunomia-bpf)

**一个帮助你更容易构建和分发eBPF程序的编译器和运行时框架。**

## 简介

`eunomia-bpf`是一个动态加载库/运行时以及一个编译工具链框架，旨在帮助您更容易地构建和分发eBPF程序。

有了eunnomia-bpf，您可以：

- 简化 `编写` eBPF 程序的库：
  - 简化构建 CO-RE [^1] `libbpf` eBPF应用程序：[仅编写 eBPF 内核代码](documents/introduction.md#simplify-building-co-re-libbpf-ebpf-applications)，并通过 `perf event`或 `ring buffer` 自动暴露您的数据从内核。
  - [自动采样数据](documents/introduction.md#automatically-sample-the-data-and-print-hists-in-userspace) 从哈希映射并在用户空间打印直方图。
  - [自动生成](documents/introduction.md#automatically-generate-and-config-command-line-arguments) 并配置 eBPF 程序的`命令行参数`。
  - 您可以同时以 `BCC` 或 `libbpf` 的方式编写内核部分。
- 使用 `Wasm`[^2] 构建eBPF程序：参见 [`Wasm-bpf`](https://github.com/eunomia-bpf/wasm-bpf) 项目
  - 运行时，库和工具链可以用 C/C++、Rust、Go 等[以 Wasm 编写 eBPF](https://github.com/eunomia-bpf/wasm-bpf)，涵盖从`跟踪`、`网络`、`安全`的使用场景。
- 简化eBPF程序的`分发`：
  - 一个[工具](ecli/)用于推送、拉取和运行预编译的eBPF程序作为Wasm模块的`OCI`镜像。
  - 以[`1`行 bash](documents/introduction.md#dynamic-load-and-run-co-re-ebpf-kernel-code-from-the-cloud-with-url-or-oci-image)从 `云端` 或 `URL` 运行eBPF程序，无需重新编译，独立于内核版本和架构。
  - 使用 `JSON` 配置文件或 `Wasm` 模块[动态加载](bpf-loader-rs) eBPF 程序。

更多信息，请参见[documents/introduction.md](documents/introduction.md)。

[^1]: CO-RE: [编译一次 – 在任何地方运行](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)
[^2]: WebAssembly 或 Wasm: <https://webassembly.org/>

## 开始使用

- Github模板：[eunomia-bpf/ebpm-template](https://github.com/eunomia-bpf/ebpm-template)
- 示例bpf程序：[examples/bpftools](examples/bpftools/)
- 教程：[eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)

### 作为 CLI 工具或服务运行

您可以通过以下方式从云中运行预编译的eBPF程序到内核，只需`1`行bash命令：

```bash
# 从https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli 下载发布版本
$ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
$ sudo ./ecli run https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/package.json # 从URL简单地运行一个预编译的ebpf代码
INFO [bpf_loader_lib::skeleton] Running ebpf program...
TIME     PID    TPID   SIG    RET    COMM   
01:54:49  77297 8042   0      0      node
01:54:50  77297 8042   0      0      node
01:54:50  78788 78787  17     0      which
01:54:50  78787 8084   17     0      sh
01:54:50  78790 78789  17     0      ps
01:54:50  78789 8084   17     0      sh
01:54:50  78793 78792  17     0      sed
01:54:50  78794 78792  17     0      cat
01:54:50  78795 78792  17     0      cat

$ sudo ./ecli run ghcr.io/eunomia-bpf/execve:latest # 使用一个名称运行并从我们的仓库下载最新版本的bpf工具
[79130] node -> /bin/sh -c which ps 
[79131] sh -> which ps 
[79132] node -> /bin/sh -c /usr/bin/ps -ax -o pid=,ppid=,pcpu=,pmem=,c 
[79133] sh -> /usr/bin/ps -ax -o pid=,ppid=,pcpu=,pmem=,command= 
[79134] node -> /bin/sh -c "/home/yunwei/.vscode-server/bin/2ccd690cbf 
[79135] sh -> /home/yunwei/.vscode-server/bin/2ccd690cbff 78132 79119 79120 79121 
[79136] cpuUsage.sh -> sed -n s/^cpu\s//p /proc/stat
```

您还可以使用服务器来管理和动态安装eBPF程序。

启动服务器：

```console
$ sudo ./ecli-server
[2023-08-08 02:02:03.864009 +08:00] INFO [server/src/main.rs:95] Serving at 127.0.0.1:8527
```

使用ecli来控制远程服务器并管理多个eBPF程序：

```console
$ ./ecli client start sigsnoop.json # 开始程序
1
$ ./ecli client log 1 # 获取程序日志
TIME     PID    TPID   SIG    RET    COMM   
02:05:58  79725 78132  17     0      bash
02:05:59  77325 77297  0      0      node
02:05:59  77297 8042   0      0      node
02:05:59  77297 8042   0      0      node
02:05:59  79727 79726  17     0      which
02:05:59  79726 8084   17     0      sh
02:05:59  79731 79730  17     0      which
```

有关更多信息，请参见[documents/src/ecli/server.md](documents/src/ecli/server.md)。

## 安装项目

- 安装`ecli`工具以从云端运行eBPF程序：

    ```console
    $ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
    $ ./ecli -h
    ecli子命令，包括run、push、pull、login、logout

    用法: ecli-rs [PROG] [EXTRA_ARGS]... [COMMAND]

    命令:
      run     运行ebpf程序
      client  客户端操作
      push    
      pull    从注册表中提取oci图像
      login   登录到oci注册表
      logout  从注册表登出
      help    打印此消息或给定子命令的帮助

    参数:
      [PROG]           不推荐使用。只为了与旧版本兼容。Ebpf程序URL或本地路径，设置为`-`可以从stdin读取程序
      [EXTRA_ARGS]...  不推荐使用。只为了与旧版本兼容。额外的程序参数；对于wasm程序，将直接传递给它；对于JSON程序，将传递给生成的参数解析器

    选项:
      -h, --help  打印帮助
    ....
    ```

- 安装`ecc`编译器工具链，用于将eBPF内核代码编译为`config`文件或`Wasm`模块（为了编译，需要安装`clang`、`llvm`和`libclang`）：

    ```console
    $ wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
    $ ./ecc -h
    eunomia-bpf编译器
    用法: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]
    ....
    ```

  或使用docker镜像进行编译：

    ```bash
    # 对于x86_64和aarch64
    docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest # 使用docker进行编译。`pwd`应包含*.bpf.c文件和*.h文件。
    ```

- 构建编译器、运行库和工具：

  有关构建详细信息，请参见[build](documents/build.md)。

## 示例

有关简单eBPF工具和eunomia-bpf库使用的详细信息，请参见[examples](examples)。

## 许可证

MIT LICENSE
