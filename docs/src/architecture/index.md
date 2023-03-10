# 架构设计

Eunomia 包含如下几个项目：

- eunomia-bpf：一个基于 libbpf 的 CO-RE eBPF 运行时库，使用 C/C++ 语言。提供 Rust 等语言的 sdk；提供 ecli 作为命令行工具；
- eunomia-cc：一个编译工具链；
- ewasm: 一个基于 eunomia-bpf 的 wasm 运行时库，提供基于 wasm 的 eBPF 程序开发能力；
- eunomia-exporter：使用 Prometheus 或 OpenTelemetry 进行可观测性数据收集，使用 Rust 编写；
- ebpm-template：使用 Github Action 进行远程编译，本地一键运行；

目录：

- [架构概述](overview.md)
- [原理](reason.md)

架构图

![arch](../img/eunomia-arch.png)
