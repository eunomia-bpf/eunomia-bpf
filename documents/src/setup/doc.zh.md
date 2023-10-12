# 欢迎来到 eunomia-bpf

eunomia-bpf 是一个动态加载库/运行时和编译工具链框架，旨在帮助您更轻松地构建和分发 eBPF 程序。

使用 eunomia-bpf，您可以：

- 一个简化编写 eBPF 程序的库：
    - 简化构建 CO-RE1 libbpf eBPF 应用程序：只需编写 eBPF 内核代码，并自动从内核中使用 perf 事件或环形缓冲区暴露您的数据。
    - 自动从哈希映射中采样数据，并在用户空间打印统计信息。
    - 自动生成和配置 eBPF 程序的命令行参数。
    - 您可以同时使用 BCC 和 libbpf 风格编写内核部分。
- 使用 Wasm2 构建 eBPF 程序：参见 Wasm-bpf 项目
    - 运行时、库和工具链，用于使用 C/C++、Rust、Go 等在 Wasm 中编写 eBPF，覆盖跟踪、网络、安全等用例。
- 简化分发 eBPF 程序：
    - 一个工具，用于将预编译的 eBPF 程序作为 OCI 图像以 Wasm 模块形式推送、拉取和运行
    - 在不重新编译、不受内核版本和体系结构限制的情况下，使用一行 bash 命令从云端或 URL 运行 eBPF 程序。
    - 使用 JSON 配置文件或 Wasm 模块动态加载 eBPF 程序。