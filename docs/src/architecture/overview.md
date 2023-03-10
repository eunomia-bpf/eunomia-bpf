# 项目概览

eunomia-bpf 包含如下几个项目：

- eunomia-bpf：一个基于 libbpf 的 CO-RE eBPF 运行时库，使用 C/C++ 语言。提供 Rust 等语言的 sdk；提供 ecli 作为命令行工具；
- eunomia-cc：一个编译工具链；
- eunomia-exporter：使用 Prometheus 或 OpenTelemetry 进行可观测性数据收集，使用 Rust 编写；
- ebpm-template：使用 Github Action 进行远程编译，本地一键运行；

## 一个 eunomia-bpf 库

libbpf 主要功能的封装，一些用于用户开发的辅助功能。

- 提供将 ebpf 代码加载到内核并运行它的能力。
- 使用一些额外的数据来帮助加载和配置 eBPF 字节码。
- 多语言绑定：参见 [eunomia-sdks](eunomia-sdks)。 我们现在有 Rust 的 API，将来会添加更多；

### 安装运行

大多数时候安装时只需要下载对应的二进制即可：

```bash
# download the release from https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ecli
```

有关详细信息，请参见 [eunomia-bpf](eunomia-bpf) 文件夹。 借助该库，我们提供了[一个简单的 cli](https://github.com/eunomia-bpf/eunomia-bpf/releases/)，在支持 eBPF 的内核版本上，您可以简单地使用 url 或路径运行预编译 eBPF 数据：

```bash
sudo ./ecli run https://eunomia-bpf.github.io/ebpm-template/package.json # simply run a pre-compiled ebpf code from a url
```

可以使用容器进行编译, 仅需要专注于编写[内核态代码](examples/bpftools/bootstrap/bootstrap.bpf.c):

```bash
docker run -it -v ./examples/bpftools/bootstrap:/src yunwei37/ebpm:latest
sudo ./ecli run examples/bpftools/bootstrap/package.json              # run the compiled ebpf code
```

更多的例子请参考 [examples/bpftools](examples/bpftools) 文件夹.

### 用于生成预编译 eBPF 数据的编译工具链

有关详细信息，请参阅编译工具链 [eunomia-cc](https://github.com/eunomia-bpf/eunomia-cc)。

您也可以简单地使用 [ebpm-template](https://github.com/eunomia-bpf/ebpm-template) repo 作为 github 中的模板开始编写代码，只需推送后，Github Actions 即可以帮助您编译 CO-RE ebpf 代码！

### 一个可观测性工具

基于 async Rust 的 Prometheus 或 OpenTelemetry 自定义可观测性数据收集器: [eunomia-exporter](<[eunomia-exporter](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/eunomia-exporter)>)

可以自行编译或通过 [release](https://github.com/eunomia-bpf/eunomia-bpf/releases/) 下载

#### example

这是一个 `opensnoop` 程序，追踪所有的打开文件，源代码来自 [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c), 我们修改过后的源代码在这里: [examples/bpftools/opensnoop](<[examples/bpftools/opensnoop](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/opensnoop)>)

在编译之后，可以定义一个这样的配置文件:

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

![prometheus](https://oss.openanolis.cn/sig/stxfomyiiwdwkdrqwlnn)

您可以在任何内核版本上部署导出器，而无需依赖 `LLVM/Clang`。 有关详细信息，请参阅 [eunomia-exporter](eunomia-exporter/README.md)。
