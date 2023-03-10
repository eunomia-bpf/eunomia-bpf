# eBPF开发框架研究

## 问题

对于开发和使用， eBPF 应用而言还可能存在哪些不够方便的地方？

搭建和开发 eBPF 程序是一个门槛比较高、比较复杂的工作，必须同时关注内核态和用户态两个方面的交互和信息处理，有时还要配置环境和编写对应的构建脚本，有没有更方便的方式？
目前不同用户态语言如 C、Go、Rust 等编写的工具难以兼容、难以统一管理，多种开发生态难以整合：如何跨架构、跨语言和内核版本，使用标准化的方式方便又快捷的打包、分发、发布二进制 eBPF 程序，同时还需要能动态调整 eBPF 程序的挂载点、参数等等？
如何更方便地使用 eBPF 的工具：类似 docker 那样？或者把 eBPF 程序作为服务运行，通过 HTTP 请求和 URL 即可热更新、动态插拔运行任意一个 eBPF 程序？

如何更方便地编写、编译、分发、使用 eBPF 程序？

## 分成两个部分：eunomia-bpf 和 wasm-bpf

eunomia-bpf

eunomia-bpf 是一个开源的 eBPF 动态加载运行时和开发工具链，是为了简化 eBPF 程序的开发、构建、分发、运行而设计的，基于 libbpf 的 CO-RE 轻量级开发框架。

使用 eunomia-bpf ，可以：

在编写 eBPF 程序或工具时只编写 libbpf 内核态代码，自动获取内核态导出信息；
使用 Wasm 进行用户态交互程序的开发，在 Wasm 虚拟机内部控制整个 eBPF 程序的加载和执行，以及处理相关数据；
eunomia-bpf 可以将预编译的 eBPF 程序打包为通用的 JSON 或 Wasm 模块，跨架构和内核版本进行分发，无需重新编译即可动态加载运行。
eunomia-bpf 由一个编译工具链和一个运行时库组成, 对比传统的 BCC、原生 libbpf 等框架，大幅简化了 eBPF 程序的开发流程，在大多数时候只需编写内核态代码，即可轻松构建、打包、发布完整的 eBPF 应用，同时内核态 eBPF 代码保证和主流的 libbpf, libbpfgo, libbpf-rs 等开发框架的 100% 兼容性。需要编写用户态代码的时候，也可以借助 Webassembly 实现通过多种语言进行用户态开发。和 bpftrace 等脚本工具相比, eunomia-bpf 保留了类似的便捷性, 同时不仅局限于 trace 方面, 可以用于更多的场景, 如网络、安全等等。

## wasm-bpf

一个 WebAssembly eBPF 库和运行时， 由 [CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)(一次编写 – 到处运行) [libbpf](https://github.com/libbpf/libbpf) 和 [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) 强力驱动。

- `通用`: 给 Wasm 提供大部分的 eBPF 功能。 比如从 `ring buffer` 或者 `perf buffer` 中获取数据、 通过 `maps` 提供 `内核` eBPF 和 `用户态` Wasm 程序之间的双向通信、 动态 `加载`, `附加` 或者 `解除附加` eBPF程序等。 支持大量的 eBPF 程序类型和 map 类型， 覆盖了用于 `tracing（跟踪）`, `networking（网络）`, `security（安全）` 的使用场景。
- `高性能`: 对于复杂数据类型，没有额外的 `序列化` 开销。 通过 `共享内存` 来避免在 Host 和 Wasm 端之间的额外数据拷贝。
- `简单便捷的开发体验`: 提供和 [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) 相似的开发体验， `自动生成` Wasm-eBPF 的 `skeleton` 头文件以及用于绑定的 `类型` 定义。
- `非常轻量`: 运行时的示例实现只有 `300+` 行代码, 二进制文件只有 `1.5 MB` 的大小。 编译好的 Wasm 模块只有 `~90K` 。你可以非常容易地使用任何语言，在任何平台上建立你自己的 Wasm-eBPF 运行时，使用相同的工具链来构建应用！

## details

- 关于 wasm 能给 ebpf 带来什么好处，以及 wasm-bpf 的设计方案，请参考 introduce-to-wasm-bpf-bpf-community.md
- 关于 eunomia-bpf 的改进，请参考 0.3.0-release.md
- 关于具体的使用示例和截图，请参考 PPT
