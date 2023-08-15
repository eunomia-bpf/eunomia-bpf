# eunomia-bpf: Looking forward to 2023, let eBPF sprout wings with Wasm

Looking back at 2022, two technologies have received a lot of attention: eBPF and WebAssembly.

## eBPF: New Possibilities

eBPF is a revolutionary technology that originated in the Linux kernel and allows sandbox programs to run in the kernel of an operating system. It is used to securely and efficiently extend the functionality of the kernel without changing its source code or loading kernel modules.

In the past year, observability technology has received significant attention and has been listed by Gartner as one of the top ten strategic technology trends for 2023. eBPF itself is a great complement to traditional observability capabilities. Without invasive modifications to the kernel, it dynamically inserts its own code into the kernel to achieve various monitoring and tracing capabilities. At the same time, eBPF has also promoted the development of a new generation of tools in areas such as networking, security, application configuration tracking, and performance troubleshooting. These tools no longer rely on existing kernel functionality, but actively re-run without affecting execution efficiency or security.

Today, eBPF is widely used in cloud native, observability, performance optimization, security, hardware acceleration, and other fields. Its application scenarios are rapidly expanding, and innovative projects based on eBPF technology are emerging. For the operating systems community, eBPF technology brings a whole new realm of possibilities and opportunities. The era of eBPF has arrived.

Looking back at the eBPF Summit 2022, "The future of eBPF in the Linux Kernel" outlined the development direction of eBPF-related technologies. The specific evolution path may include the following aspects:

- More comprehensive programming semantic support: The current programming capabilities of eBPF have some limitations (such as the lack of support for variable-bound loops and limited instruction counts). In the future, it is hoped to further provide Turing-complete programming capabilities for eBPF, enhancing its abilities in looping, memory allocation, and other language features.
- Stronger security: Support type safety, enhance runtime verifier, hope that BPF can provide security programming capabilities comparable to Rust, and explore the possibility of combining Rust and BPF features to provide further kernel functionality that is both portable and secure.
- Broader portability: Enhance CO-RE, strengthen the portability of helper interfaces, and realize cross-architecture and cross-platform portability.
- Stronger kernel programmability: Support access/modification of any kernel parameters and return values, achieve stronger kernel programming capabilities, and even use BPF to help build and enhance kernel security.

## Wasm: Leading the next generation computing paradigm

While eBPF primarily focuses on the kernel space or kernel-related applications, WebAssembly (Wasm) in the user space also became a new focus in 2022.

WebAssembly, abbreviated as Wasm, is a technology with great potential from its inception. Initially designed as a portable bytecode-like instruction format standard for compiling high-level languages such as C/C++/Rust, it enables client and server applications to be deployed in web browsers. To this day, WebAssembly is evolving beyond the two domains indicated by its name, Web and Assembly. By using runtime environments compatible with Wasm, Wasm files can be executed on both the client and server sides. It has covered almost all emerging fields, from being dubbed the "JavaScript killer" to being considered the next frontiers of cloud computing. It has also made its way from cloud computing and serverless to edge computing. Wasm has far surpassed its role as the fourth web standard language and has redefined the development model of application software, gradually approaching its vision of "write once, run anywhere."

Wasm has several key design goals that have attracted attention since its inception:

- Portability: Wasm is designed to target low-level virtual machine architectures. Its instructions are translated into machine code by the physical machine separately. This means that Wasm binary files can ultimately run on various operating systems and chip architectures, whether in browsers running on X86 laptops or on servers inside or in the cloud, on mobile devices, IoT devices, and so on.
- Multi-language: Since Wasm is a compilation target, the specific language used for programming modules is not important. What matters is whether there is support for compiling that language into Wasm. Developers can flexibly use a variety of languages (such as C, C++, Rust, Ada, etc.) to build binary files and enjoy the benefits of Wasm.
- Lightweight and efficient: As a low-level binary instruction format, Wasm requires fewer operations to translate it into optimized machine code.
- Security: One of the goals of Wasm is security. It executes in a sandbox environment with no initial visibility into the host runtime. This means that access to system resources (such as the file system and hardware) is restricted unless corresponding functions are explicitly imported to support it. Thus, Wasm greatly limits the attack surface and enables the secure execution of untrusted code in a multi-tenant environment.In the past year of 2022, Wasm has achieved many exciting accomplishments. 
Many new Wasm startups have emerged, and established cloud service providers and companies have announced their support for Wasm. 
The Bytecode Alliance has introduced many new Wasm standards and CNCF has hosted two WasmDay events. 
One of the largest users of Wasm, Figma, was acquired by Adobe for an astonishing $20 billion. 
For WebAssembly, 2023 is likely to be another breakout year:

- The component model describes how Wasm binary files interact with each other and is rapidly maturing with reference implementations already available. 
Developers can declare which components their applications need, or more abstractly, which functionalities their applications require (rather than searching for libraries in their preferred source language). 
Then the Wasm runtime can assemble the correct set of components on behalf of the user. 
2023 will be the year when the component model starts to redefine how we write software.
- Wasm has changed the potential of serverless environments. 
Due to almost instantaneous startup time, smaller binary file size, and platform and architecture neutrality, Wasm binary files can be executed with a fraction of the resources required by today's serverless infrastructure.
- At the end of 2022, the OCI Registry working group announced an official way to store content other than container images. 
This could include Helm charts, photos, or Wasm applications. 
This new feature is called "Artifact Storage."
- All major programming languages will be supported by Wasm: The Wasm GC proposal is likely to be available and supported in early 2023, so Kotlin and Dart will soon release Wasm compilers, and Java is also likely to become the most popular Wasm development language.

## Coolbpf + eunomia-bpf = eunomia-lcc

In the past year, Alibaba Cloud Dragon Lizard Community Operations SIG officially open-sourced the Coolbpf project. 
Based on CO-RE (Compile Once-Run Everywhere), Coolbpf retains advantages such as low resource consumption and strong portability, and incorporates dynamic compilation features of BCC, greatly simplifying the development, compilation, and runtime efficiency through remote service capabilities, and is suitable for deploying applications in production environments in batches. 
Coolbpf also supports running on low kernel versions without eBPF features by providing an eBPF driver, ensuring safe operation on low versions from both kernel space and the perspective of batch deployment, and greatly enhancing the ability of eBPF programs to "compile once, run everywhere."

eunomia-bpf is also a universal, lightweight, multi-language next-generation eBPF development framework/component library combined with Wasm. 
It was initiated and incubated in the Alibaba Cloud Dragon Lizard Community's "eBPF Technology Exploration SIG" in the second half of 2022. 
eunomia-bpf includes a runtime and a toolchain and focuses on improving the development and usage experience of eBPF programs in user space. 
It has three main features:

1. Only kernel space code needs to be written to run eBPF programs. 
The kernel space frontend is fully compatible with various syntaxes such as bcc and native libbpf, reducing the learning cost and improving development efficiency for eBPF.
2. The compilation toolchain and the runtime are completely separated, ensuring compatibility between different versions of the compilation toolchain and the runtime. 
They are loaded in the CO-RE manner (compile once, run everywhere), reducing resource consumption for deployment and usage. 
It also allows code similar to BCC/bpftrace to support AOT compilation without relying on libraries like llvm at runtime, while retaining the simplicity of bpftrace-like scripting usage.
3. User space also supports multiple languages, such as C++/C/Rust, for developing eBPF programs with Wasm. 
The user space programs can be distributed and dynamically loaded as Wasm modules or as JSON/YAML configuration files. 
They can also be stored and managed as Wasm OCI images, which can include user space and kernel space eBPF applications.

eunomia-bpf hopes to provide a framework in the form of libraries or loosely coupled components to explore more in compiling, building, distributing, and running eBPF programs, making it easier for other companies and individuals to build a similar user space development and runtime environment, or a complete development platform and plugin runtime, based on their own kernel space eBPF infrastructure.

At the end of 2022, we attempted to combine Coolbpf and eunomia-bpf to create a new eBPF user space development library [eunomia-lcc](https://gitee.com/anolis/coolbpf/pulls/17). 
With the support of low kernel versions provided by Coolbpf and the ability to deploy applications in batches, as well as the user space development and distribution features provided by eunomia-bpf combined with Wasm, we created a new eBPF user space development library within the framework of Coolbpf. 
With eunomia-lcc, Coolbpf can now:

- Automatically retrieve kernel space export information, generate command-line parameters, histogram outputs, etc., by only writing kernel space code when writing eBPF programs or tools.
- Use Wasm for developing user space interactive programs, control the loading and execution of the entire eBPF program, and process data reported by eBPF within the Wasm virtual machine.- Precompiled eBPF programs can be packaged as universal JSON or Wasm modules for distribution across architectures and kernel versions without the need for recompilation and can be dynamically loaded and executed.

At the same time, Coolbpf features such as low version compatibility, automatic BTF acquisition, remote compilation, etc. can be preserved, making eBPF program development more convenient.

Looking ahead, the eunomia-bpf team also hopes to explore, improve, and enhance the process, tools, SDK for eBPF program development, compilation, packaging, publishing, installation, and upgrading in 2023. They actively provide feedback to the upstream community to further enhance the programming experience and language capabilities of eBPF. They also aim to combine it further with WebAssembly, exploring and practicing more in terms of observability, serverless, programmable kernel, etc., moving towards Turing completeness and better language support.

## References

1. Wasm will lead the next generation of computing paradigms (Translated): <https://www.oschina.net/news/214580>
2. WebAssembly: 5 predictions for 2023: <https://www.sohu.com/a/626985661_121119003>
3. eBPF Technology Research SIG Homepage: [https://openanolis.cn/sig/ebpfresearch](https://openanolis.cn/sig/ebpfresearch)
4. Coolbpf Project Repository: <https://gitee.com/anolis/coolbpf>
5. eunomia-bpf Dragon Lizard Community Mirror Repository: [https://gitee.com/anolis/eunomia](https://gitee.com/anolis/eunomia)
6. eunomia-bpf Github Repository: <https://github.com/eunomia-bpf/eunomia-bpf>
7. When Wasm meets eBPF: Writing, distributing, loading, and running eBPF programs with WebAssembly | Dragon Lizard Technology: <https://developer.aliyun.com/article/1050439>
8. 2023, will observability requirements have an "explosive year"? <https://36kr.com/p/dp2063589382737542>