# eunomia-bpf: 一个基于WASM的CO-RE epf程序动态加载框架

[![Actions Status](https://github.com/eunomia-bpf/eunomia-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/eunomia-bpf/actions)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/eunomia-bpf/eunomia-bpf)](https://github.com/eunomia-bpf/eunomia-bpf/releases)
<!-- [![codecov](https://codecov.io/gh/eunomia-bpf/eunomia-bpf/branch/master/graph/badge.svg)](https://codecov.io/gh/filipdutescu/modern-cpp-template) -->

## 我们的目标

在eunomia-bpf中，你可以:

- 在不提供或管理基础设施的情况下运行CO-RE epf代码
- 只编写eBPF内核代码并且将他编译为JSON，动态加载到另一台机器上而不需要重新编译
- 将eBPF程序编译为WASM模块，就可以在用户空间WASM运行时时控制eBPF程序或处理数据
- 拥有非常小和简单的可执行程序！库本身 `< 1MB` 且不依赖 `LLVM/Clang`，可以轻松嵌入到项目中
- 以`< 100ms`的速度动态加载和运行任何eBPF程序，比bcc更迅速

为了更普遍地应用，我们开发了一种编译、传输和运行大多数libbpf CO-RE对象的方法，其中包含一些用户空间配置元数据，以帮助您加载和操作eBPF字节代码。eBPF的编译和运行阶段是完全分离的，因此，在加载epf程序时，只需要eBPF字节码和数kB元数据。

大多数时候，您需要做的唯一一件事就是专注于在内核中编写单个epf程序。如果您希望有一个用户空间程序来操作eBPF程序，那么您可以编写一个`WASM`模块来完成它。

## 项目架构
我们有一个加载器库，一个编译工具链，以及一些额外的工具，如cli和一个自定义指标导出器。


### 一个eunomia-bpf库
这个库包含了libbpf地主要函数，提供了将eBPF代码动态加载到内核的能力，并使用简单的JSON和API运行它。


## Our function

eunomia-bpf 包含如下几个项目：

- eunomia-bpf：一个基于 libbpf 的 CO-RE eBPF 运行时库，使用 C/C++ 语言。提供 Rust 等语言的 sdk；提供 ecli 作为命令行工具；
- eunomia-cc：一个编译工具链；
- eunomia-exporter：使用 Prometheus 或 OpenTelemetry 进行可观测性数据收集，使用 Rust 编写；
- ebpm-template：使用 Github Action 进行远程编译，本地一键运行；

### 一个eunomia-bpf库

libbpf 主要功能的封装，一些用于用户开发的辅助功能。

- 提供将 ebpf 代码加载到内核并运行它的能力。
- 使用一些额外的数据来帮助加载和配置 eBPF 字节码。
- 多语言绑定：参见 [eunomia-sdks](eunomia-sdks)。 我们现在有 Rust 的 API，将来会添加更多；

#### 安装运行

大多数时候安装时只需要下载对应的二进制即可：

```bash
$ # download the release from https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli
$ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ecli
```

有关详细信息，请参见 [eunomia-bpf](eunomia-bpf) 文件夹。 借助该库，我们提供了[一个简单的 cli](https://github.com/eunomia-bpf/eunomia-bpf/releases/)，在支持 eBPF 的内核版本上，您可以简单地使用 url 或路径运行预编译 eBPF 数据：

```bash
$ sudo ./ecli run https://eunomia-bpf.github.io/ebpm-template/package.json # simply run a pre-compiled ebpf code from a url
```

可以使用容器进行编译, 仅需要专注于编写[内核态代码](examples/bpftools/bootstrap/bootstrap.bpf.c):

```bash
$ docker run -it -v ./examples/bpftools/bootstrap:/src yunwei37/ebpm:latest
$ sudo ./ecli run examples/bpftools/bootstrap/package.json              # run the compiled ebpf code
```

更多的例子请参考 [examples/bpftools](examples/bpftools) 文件夹.

### 用于生成预编译 eBPF 数据的编译工具链

有关详细信息，请参阅编译工具链 [eunomia-cc](https://github.com/eunomia-bpf/eunomia-cc)。

您也可以简单地使用 [ebpm-template](https://github.com/eunomia-bpf/ebpm-template) repo 作为 github 中的模板开始编写代码，只需推送后，Github Actions 即可以帮助您编译 CO-RE ebpf 代码！

### 一个可观测性工具

An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: [eunomia-exporter](eunomia-exporter)

You can compile it or download from [release](https://github.com/eunomia-bpf/eunomia-bpf/releases/)

#### example

This is an adapted version of opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c), you can check our source code here: [examples/bpftools/opensnoop](examples/bpftools/opensnoop)

After compile the eBPF code, you can define a config file like this:

```yml
programs:
- name: opensnoop
  metrics:
    counters:
    - name: eunomia_file_open_counter
      description: test
      labels:
      - name: pid
      - name: comm
      - name: filename
        from: fname
  compiled_ebpf_filename: examples/bpftools/opensnoop/package.json
```

然后，您可以在任何地方使用 `config.yaml` 和预编译的 eBPF 数据 `package.json` 启动 Prometheus 导出器，您可以看到如下指标：

![opensnoop_prometheus](documents/images/opensnoop_prometheus.png)

您可以在任何内核版本上部署导出器，而无需依赖 `LLVM/Clang`。 有关详细信息，请参阅 [eunomia-exporter](eunomia-exporter/README.md)。

## 计划路线图

- [X] 重构 `Eunomia` 项目中的代码并提供快速示例
- [X] 支持用户空间中的`tracepoints`、`fentry`、`kprobe`、`lsm`和`ring buffer`/`perf event`输出。
- [X] 使编译更容易使用，更灵活，完全兼容其他 libbpf 程序；
- [X] 添加可配置的可观测性导出器
- [ ] 使用 lua 进行 ebpf 包加载配置，并添加更多 ebpf 程序类型支持
- [ ] 支持更多的 ebpf 程序类型：
- [ ] 为 eunomia-bpf 添加简单的包管理器
- [ ] 从 `libbpf` 添加更多可能性
- [ ] 提供 python、go 等 sdk
- [ ] 添加对 `etcd` 的支持并增强服务器
- [ ] 修复 ci 和 docs

## License

MIT LICENSE

