# eunomia-bpf

[eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) 是一个开源的 eBPF 动态加载运行时和开发工具链，是为了简化 eBPF 程序的开发、构建、分发、运行而设计的基于 libbpf 的轻量级开发框架。使用 eunomia-bpf ，可以在编写 eBPF 程序或工具时只编写内核态代码，自动获取内核态导出信息，或使用 Wasm 进行用户态交互程序的开发，在 Wasm 虚拟机内部控制整个 eBPF 程序的加载和执行。eunomia-bpf 可以将预编译的 eBPF 程序打包为通用的 JSON 或 Wasm 模块，跨架构和内核版本进行分发，无需重新编译即可动态加载运行。

我们已经测试了在 x86、ARM 等不同架构、不同内核版本的 Linux 系统上，对于一个基于 eBPF 的工具或模块，eunomia-bpf 框架都可以使用同一个预编译 eBPF 程序二进制，从云端一行命令获取到本地之后直接运行，不需要类似 BCC 一样再使用 LLVM/Clang 进行本地编译，也能嵌入其他应用中作为插件运行且具有良好的隔离性。我们希望能尝试在 RISC-V 系统上完成移植和测试，实现架构无关的 eBPF 工具的移植和运行。

工作内容:

1. 将 eunomia-bpf 的运行时模块移植到 RISC-V 系统上（主要是 Webassembly 运行时和 libbpf 库）
2. 将 [BCC](https://github.com/iovisor/bcc) 中基于 libbpf 的工具移植到 Webassembly 并进行测试，尝试让编译产物在 RISC-V、x86、ARM 或其他指令集的内核上都可以正常运行；
3. 尝试移植更多 eBPF 的开发框架和工具到 WebAssembly，并为基于 Webassembly 的 eBPF 程序开发和运行提供更多的用户态开发库和工具链；
4. 尝试进行更多基于 eBPF 和 WebAssembly 的相关探索和实现，重构现有的开发框架和工具链，和 WebAssembly、eBPF 相关上游社区进行交流和推进；目前的核心代码量其实很少（~2k），主要使用 C/C++ 完成，我们希望接下来使用 Rust 完成一些重构和重新设计的工作，支持更多的 eBPF 程序类型和相关 API；

岗位要求:

1. 对 WebAssembly 和 eBPF 技术感兴趣，对二者有一些初步的了解或者有一些 demo 尝试（花个一两天看看就好）
2. 了解 C/C++，对于操作系统有一些了解（按照我们在 ARM 上面的经验来说，完成移植工具和测试工作应该不是很困难，预计 LV2 就够？）
3. 了解 BTF 格式信息，了解 Rust 语言，对于 eBPF 的实现机制或 WebAssembly 相关生态有一些深入的理解（可选）
