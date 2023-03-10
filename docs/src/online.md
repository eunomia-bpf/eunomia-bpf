# 在线体验网站

可使用 bolipi 提供的在线体验服务，在线编译，在线运行、在线获取可视化结果：[https://bolipi.com/ebpf/home/online](https://bolipi.com/ebpf/home/online)

![imga](../img/online.png)

## 通过在线编译运行快速体验 eBPF 和可视化

本在线编译平台由 `eunomia-bpf` 工具链提供支持，详细文档请参考 [eunomia-bpf.github.io/](https://eunomia-bpf.github.io/)

### 在线编译

在代码编辑器中编写 eBPF 的内核态程序，应当遵循 libbpf-tools 的内核态代码编写约定，即：

- `代码编辑器` (\*.bpf.c) 包含 BPF C 代码，它被编译成 package.json
- `头文件编辑器` (\*.h) 可以选择包含通过 perf event 或环形缓冲区导出到用户空间的类型

我们目前只支持使用基于 libbpf 的内核态代码，BCC 代码支持由于存在一些语法上的差异，还在开发中。

编写完成代码后，点击 `编译` 按钮即可编译成 eBPF 的内核态程序，在 `编译输出` 中查看编译输出：

![imgb](../img/compile-output.png)

更多信息请参考：[eunomia-bpf.github.io/mannual.html](https://eunomia-bpf.github.io/mannual.html)

更多例子请参考：[https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools)

### 在线运行

点击右侧的绿色运行按钮运行：

![imgc](../img/run-ebpf.png)

也可以通过 `下载编译后的文件` 查看编译好的程序，并在本地使用 `ecli` 直接运行：

```console
$ # 下载安装 ecli 二进制
$ wget https://aka.pw/bpf-ecli -O ./ecli && chmod +x ./ecli
$ # 运行 eBPF 程序（root shell）
$ sudo ./ecli run package.json
```

### 使用 Prometheus 在线获取可视化结果

点击 `运行可视化组件` 按钮，在弹出的窗口中配置 prometheus metrics 信息:

![imgd](../img/prometheus-config.png)

点击 `确定` 即可跳转到 Prometheus 界面，可通过选择 graph 查看可视化结果：

![imgd](../img/prometheus-graph.png)

## 关于 eunomia-bpf

eunomia-bpf 是一套编译工具链和运行时，以及一些附加项目，我们希望做到让 eBPF 程序：

- 让 eBPF 程序的编译和运行过程大大简化，抛去繁琐的用户态模板编写、繁琐的 BCC 安装流程，只需要编写内核态 eBPF 程序，编译后即可在不同机器上任意内核版本下运行，并且轻松获取可视化结果。
- 真正像 JavaScript 或者 Wasm 那样易于分发和运行，或者说内核态或可观测性层面的 FaaS：eBPF 即服务，通过 API 请求快速分发和运行，无需管理基础设施和用户态加载程序；
