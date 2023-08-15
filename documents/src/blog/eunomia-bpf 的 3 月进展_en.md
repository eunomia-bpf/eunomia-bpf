# Progress of eunomia-bpf in March

The eunomia-bpf project is an open-source project aimed at providing a set of tools for writing and running eBPF programs more conveniently in the Linux kernel. In the past month, the project has made some new progress. Here is an overview of these advances.

Firstly, the eunomia-bpf dynamic loading library has undergone some important updates. The library now supports the btf hub, which makes it easier to port eBPF programs on low kernel versions. The ecli program has also been completely rewritten and is now written in Rust, replacing the original version written in C++. In addition, the library has fixed the output issue when using JSON to dynamically load eBPF programs and automatically publishes Docker images in CI.

Secondly, the Wasm-bpf project has also been updated. The project has added a series of examples that focus on security, networking, tracing, and other areas. The Wasm-bpf project has also added support for the Guest SDK in the Rust language and attempted to add support for the Guest SDK in the Go language. The runtime implementation of Rust and wasmtime has also been included in the project, and a runtime plugin has been added for WasmEdge. Furthermore, the project has undergone a series of fixes and documentation refactoring and has improved CI and testing. The project has also attempted to use the Wasm component model and added a tool for adding table exports defined in the wasm module. Lastly, the project has produced three blog posts and demonstration videos.

Lastly, eunomia-bpf has added a new demo project called GPTtrace. This project uses ChatGPT to automate the generation of eBPF programs and tracing, making it easier for users to create and trace custom system events. The project has also updated the tutorial documentation to make it easier to use.

Overall, the eunomia-bpf project has made significant progress in March. These updates and improvements make the project more user-friendly and flexible, expanding its functionality and scope. If you are interested in the project, you can follow its latest developments and updates.

Here is a more detailed list of updates:

- eunomia-bpf dynamic loading library
  - Added support for the btf hub, allowing better portability of eBPF programs on low kernel versions [link](https://github.com/eunomia-bpf/eunomia-bpf/pull/150)
  - Completely replaced the version written in C++ with ecli written in Rust [link](https://github.com/eunomia-bpf/eunomia-bpf/pull/139)
  - Fixed the output issue when using JSON to dynamically load eBPF programs [link](https://github.com/eunomia-bpf/eunomia-bpf/pull/149) [link](https://github.com/eunomia-bpf/eunomia-bpf/pull/136)
  - Automatically publishes Docker images in CI [link](https://github.com/eunomia-bpf/eunomia-bpf/pull/129) [link](https://github.com/eunomia-bpf/eunomia-bpf/pull/135)
  - Tried to add support on other platforms and performed more testing on RISC-V [link](https://github.com/eunomia-bpf/eunomia-bpf/discussions/147)
- Wasm-bpf
  - Added a series of examples focusing on security, networking, tracing, and more [link](https://github.com/eunomia-bpf/wasm-bpf/pull/11) [link](https://github.com/eunomia-bpf/wasm-bpf/pull/4) [link](https://github.com/eunomia-bpf/wasm-bpf/pull/26)
  - Added support for the Guest SDK in the Rust language [link](https://github.com/eunomia-bpf/wasm-bpf/pull/9)
  - Attempted to add support for the Guest SDK in the Go language [link](https://github.com/eunomia-bpf/wasm-bpf/pull/37)
  - Added the runtime implementation of Rust and wasmtime [link](https://github.com/eunomia-bpf/wasm-bpf/pull/33)
  - Added a runtime plugin for WasmEdge [link](https://github.com/WasmEdge/WasmEdge/pull/2314).- A series of minor fixes and documentation refactorings [link](https://github.com/eunomia-bpf/wasm-bpf/pull/51) [link](https://github.com/eunomia-bpf/wasm-bpf/pull/39) [link](https://github.com/eunomia-bpf/wasm-bpf/pull/40) [link](https://github.com/eunomia-bpf/wasm-bpf/pull/51) [link](https://github.com/eunomia-bpf/wasm-bpf/pull/17)
  - Improvement of CI, testing, etc. [link](https://github.com/eunomia-bpf/wasm-bpf/pull/44) [link](https://github.com/eunomia-bpf/wasm-bpf/pull/33)
  - Attempt of Wasm component model [link](https://github.com/eunomia-bpf/c-rust-component-test)
  - A tool to add an export of the table defined in the wasm module [link](https://github.com/eunomia-bpf/add-table-export)
  - Production of three blogs and demo videos, etc.
- New demo project: GPTtrace: Generate eBPF programs and tracing with ChatGPT and natural language [link](https://github.com/eunomia-bpf/GPTtrace)
  - Improvement of tutorial documentation: [link](https://github.com/eunomia-bpf/bpf-developer-tutorial)
