# 系统设计草稿（2022.08）

## 核心: 一个运行时库 eunomia-bpf

有三个核心部分：

- 从 CO-RE 的 libbpf 库中抽象出最小的和 ebpf 字节码以及重定位所需相关信息，生成所需的 data：需要一些 clang 插件或者解析语法树的东西；
- 根据生成的 data，进行装配 CO-RE 启动和热加载注入内核的 API，不依赖于任何运行时编译工具链；
- 其他的一些辅助函数 API，例如停止 ebpf 追踪器、访问对应的 map 信息；可以嵌入一个 lua 虚拟机来进行一些配置；

目前是使用 C++ 和 C 编写：
单线程，体积尽可能小；

可能的完善方向：

- 目前使用 C++20（这个主要是为了看起来比较有趣和自己学习使用，用了不少14/17/20的特性），降低版本，接口使用 C，以实现更好的兼容性以及对于嵌入式设备更好的适配性；
- 更好的协议格式: 需要解决用什么格式存储，需不需要压缩的问题；提供多种可选格式；
- 更多的测试：基于不同内核版本、不同的跟踪类型：一个 github actions 的测试框架；
- 不同的语言绑定；
- 专注于 ebpf，不需要解决用户态的导出的问题；也可以提供一个可选的 c 或者 lua 的解释器，作为用户态代码的更新方案；
- 提供回调接口或者别的一些访问 map 的方式来处理；
- 对融合，或者说 ebpf 程序提供感知；clang 插件来帮助导出 ebpf 相关信息；
- 需要注意一下不同内核版本之间的 libbpf 的兼容性；

例如：

```cpp
ebpf_program = eunomia_decode(recived_buffer);
ebpf_program.run();
ebpf_program.stop();
ebpf_program.process_message(reciver);
```

```c
ebpf_program = eunomia_decode(recived_buffer);
run_ebpf_program(ebpf_program);
stop_ebpf_program(ebpf_program);
ebpf_program.process_message(reciver);
```

API 设计：

- 原子：
- 正交：

## 基于运行时库的一个 cli

一个 ebpf 程序包含两个部分：

- 用户态的一些处理代码，一些用来处理 ebpf 程序上报的信息的 handlers
- 内核态的编译好的 ebpf 程序（可以不止一个）

假设我们有一个 ebpf 探针或者说追踪器叫 opensnoop，eunomia-cli 它有如下功能：

- 可以一键运行；
- bash
- /bin/bash ./bash

    ```bash
    ./ecli run opensnoop                                                     # 使用一个名字
    ./ecli run https://github.com/ebpf-io/raw/master/examples/opensnoop.bpf.json  # 使用一个http API
    ./ecli run ./opensnoop.bpf.json                                               # 使用一个本地路径
    ```

    第一种方式它会在 ~/.eunomia-bpf 的目录里面找（举个例子），或者当前目录下的，或者通过环境变量控制；

- 本地帮助生成编译框架；

  ```bash
  ./ecli init opensnoop
  ```

  需要的文件：

  - makefile
  - .gitignore
  - xxx.bpf.c
  - xxx.h
  - config.json/toml

    生成一个最简单的 libbpf-bootstrap 编译框架，不带包管理器，没有配置文件，没有依赖；需要一个镜像；

- 本地编译生成所需要的文件（需要安装 makefile、clang 等依赖）：

    ```bash
    ./ecli build opensnoop/.
    # 这一步也可以直接替换为使用 makefile
    make
    ```

- 我们需要一种语言来帮助实现可定制化的用户态程序处理，比如 lua 虚拟机来实现热加载；但是这个部分可以分开；用户态的部分应该作为类似标准库一样的东西；

改一改 eunomia 就好；

- 和 etcd 集成；
- 通过 UDP 在组播地址上监听实现发现；

### 一个包管理器：ebpm

类似于 cargo 和 wapm

- wapm 包含 ecli 的部分。这部分可以用 go 写；
- 专注于一个部分：获取 ebpf 数据文件（本质上是一个分布式文件版本管理系统），看看能不能复用 git
- 可以做成分布式、去中心化的，使用 url 进行定位；

用例：

- 角色1：普通用户/user

首先，我们有一个开发人员的用例，他想使用 ebpf 二进制文件或者程序，但不知道如何/在哪里找到它:

试着运行

```bash
./ebpm run opensnoop                                                     # 使用一个名字直接跑起来
./ebpm run https://github.com/ebpf-io/raw/master/examples/opensnoop.bpf  # 使用一个http API
./ebpm run ./opensnoop.bpf                                               # 使用一个本地路径
```

- 角色2：通用 ebpf 数据文件发布者/ebpf developer

我们的第二个角色是一个开发人员，他想要创建一个通用二进制，并在任何机器和操作系统上分发它。这对于命令行工具或者可以直接在Shell中运行的任何东西都很有用:

生成 ebpf 数据文件

```bash
./ebpm init opensnoop
./ebpm build opensnoop
```

- 需要有约束，gcc 和 linux 版本；

会产生一个配置文件模板：

```toml
[package]
name = "username/my_package"
version = "0.1.0"
description = ""
license = "MIT"

[[module]]
name = "my_app"
source = "path/to/app.ebpf"
```

发布 ebpf 数据文件

```bash
./ebpm publish opensnoop
```

我应该在哪里发布它？Github？Npm？但这只是 ebpf，没有任何语言的关联…那就Github！

git push ...

- 角色3：其他程序的开发者/ebpf 程序使用者/other developers

可以直接下载：

我们可以在任何有绑定的语言中使用 ebpf：

```bash
./ebpm get opensnoop
```

这会创建一个 config 文件；

或者在 config 里面定义之后：

ebpm.toml/json

```c
[[module]]
name = "opensnoop"、
path = ”http://....."
version = 0.1

[[module]]
name = "execsnoop"
path = ”./bpftools/execsnoop.bpf”
version = 0.1
```

运行

```bash
./ebpm install .
```

就能在本地下载并运行；

```go
import "ebpm"

handler := ebmp.open_and_run("execsnoop")
handler.stop()
handler := ebmp.open_and_run("execsnoop")
handler.stop()
```

或者更进一步，它应该可以被内嵌在别的包管理器里面，比如，我想安装一个 go 的 opensnoop 包，我只需要：

```bash
go get ebpm-opensnoop
```

```go
import "ebpm-opensnoop"
```

所有这些用例促使我们重新思考包管理器的当前全景，以及我们如何创建一个只关注 ebpf 的包管理器，它将统一以下原则:

- 它应该使发布、下载和使用 ebpf 模块变得容易；
- 它应该支持在 ebpf 之上定义命令的简单方法；
- 它应该允许不同的ABI：甚至未来的新ABI。
- 它应该可以嵌入到任何语言生态中(Python、PHP、Ruby、JS…)，而不会强迫一个生态进入另一个生态

需要注意循环依赖；
有必要的话，某些库可以有供应商依赖；

- 直接从GitHub，BitBucket，GitLab，托管Git和HTTP中提取依赖项
- 完全可重现的构建和依赖性解析
- 完全分散 - 没有中央服务器或发布过程
- 允许任何构建配置
- 私有和公共依赖，以避免“依赖地狱”
- 每个包有多个库，因此像Lerna这样的工具是不必要的
- 将单个包装从单体仓库中取出
- 完全支持语义版本控制
- 通过直接依赖于Git分支来快速移动，但是以受控方式
- 版本等效性检查以减少依赖性冲突
- TOML配置文件，便于计算机和人员编辑
- 离线工作
- 只需单击一下即可使所有内容保持最新状态

## 参考资料

- <https://wiki.lfnetworking.org/display/L3AF/L3AF%3A+Technical+Charter%2C+Milestones+and+Deliverables>

仔细看了看，我发现我们原先做的 eunomia 和这个有点类似，但是热更新原理和这个无关

- <https://github.com/solo-io/bumblebee>
- ebpf as a service
- rewrite some part of it in rust/go

## core features

- ebpf as a service

  以非常低的代价实现 ebpf 程序级别的 CO-RE 分发、远程加载、运行；类似 <https://aws.amazon.com/cn/lambda/>

## 其他

### security

在都做好之后，安全性也需要考虑清楚：要有确定性的编译结果，不能依赖于随机数或者时间之类的情况；

### 一个在网页版里面运行的 ebpf wasm 虚拟机

## 安装设计

## Remote side

```bash
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/remote-side.tar.gz -O - | tar xvf
mv remote-side/eunomiad /usr/local/bin
mv remote-side/systemd.service /usr/local/systemd/eunomiad.service
systemctl enable eunomiad
systemctl start eunomiad
```

## Dispatch side

```bash
# 下载安装 ecli 二进制
wget https://aka.pw/bpf-ecli -O /usr/local/ecli && chmod +x /usr/local/ecli
# 使用容器进行编译，生成一个 package.json 文件，里面是已经编译好的代码和一些辅助信息
docker run -it -v /path/to/repo:/src yunwei37/ebpm:latest
# 运行 eBPF 程序
cat package.json | sudo ecli run
```
