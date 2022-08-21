# tools

基于 libbpf 构建的一系列tools，分别实现了对进程、进程通信、系统调用等过程的监控和跟踪。

其中有部分代码文件和模块使我们自己编写，有部分代码文件和模块使用了第三方的代码，如：libbpf-bootstrap, bcc/libbpf-tools 等。所有引用的部分和自己开发的部分均在开头有明确标注 LICENSE 信息，例如我们自己开发的模块：

```c
/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */
```

引自第三方的代码，例如：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
```

## process

进程追踪模块通过两个tracepoint：``SEC("tp/sched/sched_process_exec")``和 ``SEC("tp/sched/sched_process_exit")``，跟踪运行着eunomia的系统中进程的执行与退出过程。当进程被执行/退出时，这两个函数:``handle_exec()``和 ``handle_exit()``会被调用，函数体中会从传入的上下文内容提取内容，将需要的信息记录在Map中。

> 进程追踪模块的信息字段：
>
> time：当前时间
>
> pid：进程id
>
> ppid：父进程id
>
> cgroupid：cgroupid
>
> usernamespace_id：usernamespace_id
>
> space_id：space_id
>
> mount_namespace_id：mount_namespace_id
>
> stat：进程状态
>
> comm：应用名/任务名
>
> filename/exitcode：调用的文件名或者进程的退出代码
>
> duration：进程运行的时间

## syscall

系统调用跟踪模块通过这个traceppoint：``SEC("tracepoint/raw_syscalls/sys_enter")``进行hook，当有syscall发生时，其经过 `sys_enter`执行点时我们的函数将会被调用，将相关信息存入map后供用户态读取。

> 系统调用跟踪模块的信息字段：
>
> time：当前时间
>
> event comm：事件名/应用名/任务名
>
> pid：进程id
>
> ppid：父进程id
>
> syscall_id：系统调用id
>

## ipc

进程通信跟踪模块使用了Linux LSM模块的钩子：``SEC("lsm/ipc_permission")``，进程间发生了通信需要检查各自的权限时便会执行，相关的信息便会被hook到用户态。

> 进程通信跟踪模块的信息字段：
>
> ts：当前时间
>
> pid：进程id
>
> uid：用户的uid（运行进程的用户id）
>
> gid：用户的gid
>
> cuid：
>
> cgid：cgroup id

## files

文件IO跟踪模块，通过kprobe对 ``SEC("kprobe/vfs_read")``和 ``SEC("kprobe/vfs_write")``进行跟踪监控。当系统发生文件IO事件，触发vfs_read或vfs_write，该模块将相关信息hook至用户态。

> 进程通信跟踪模块的信息字段：
>
> tid：tid
>
> comm： 应用名/任务名
>
> reads：read操作次数
>
> writes：write操作次数
>
> r_kb：本次读操作的io大小，kb为单位
>
> w_kb：本次写操作的io大小，kb为单位
>
> t：io操作类型：R/W
>
> file：IO流打开的文件名

## tcp

Tcp网络跟踪模块，使用kretprobe和kprobe分别对ipv4和ipv6进行监控，当系统发起或接收到基于tcp协议的网络连接请求时，触发hook机制，将网络数据五元组（源 ip、源端口、目标 ip、目标端口、协议）以及其他相关信息进行抓取，通过Map机制传输至用户态。

> tcp网络跟踪模块的信息字段：
>
> pid：进程id
>
> comm：应用名/任务名
>
> ip_type：网络协议类型：IPV4/IPV6
>
> saddr：tcp请求发起端的网络ip地址
>
> daddr：tcp请求接收端的网络ip地址
>
> dport：请求端口

## container

对于容器相关信息的监控理论上需要涉及到 `uprobe`追踪模块的内容，但目前使用现有的容器相关命令（docker top）来实现类似功能，通过对docker top这个shell命令的输出做字符串解析，得到容器在真实环境中的的pid。
## opensnoop

通过对 open 系统调用的监测，opensnoop可以展现系统内所有调用了 open 系统调用的进程信息。

> pid：进程id
>
> comm：应用名/任务名
> 
> fd: 文件描述符
> 
> err: 错误数
> 
> path: 执行路径

## mountsnoop

通过对 mount/umount 系统调用的监测，mountsnoop可以展现系统内所有调用了 mount/umount 系统调用的进程信息。

> comm: 应用名/任务名
> 
> pid: 进程id
> 
> tid: 线程id
> 
> mnt_ns: 挂载namespace
> 
> call: 执行路径

## sigsnoop

通过对系统信号量的监测，sigsnoop可以展现系统内所有系统信号量的进程信息。

> time: 执行时间
> 
> pid: 进程id  
> 
> comm: 应用名/任务名
>  
> sig: 信号量
> 
> tpid: 标签协议标识
> 
> result: 是否正常执行

## tcpconnlat

Tcp网络时延跟踪模块，当系统发起或接收到基于tcp协议的网络连接请求时，触发hook机制，将网络数据五元组（源 ip、源端口、目标 ip、目标端口、协议）以及时延进行抓取。

> pid：进程id
>
> comm：应用名/任务名
>
> saddr：tcp请求发起端的网络ip地址
>
> daddr：tcp请求接收端的网络ip地址
>
> dport：请求端口
> 
> lat(ms): tcp 请求时延

## tcprrt

Tcp网络返回时延跟踪模块。

```shell
All Addresses = ****** 
     usecs               : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 0        |                                        |
      8192 -> 16383      : 106      |************                            |
     16384 -> 32767      : 348      |****************************************|
     32768 -> 65535      : 56       |******                                  |
     65536 -> 131071     : 12       |*                                       |
    131072 -> 262143     : 8        |                                        |
```

## capable

capabilities能力权限控制模块

## seccomp

seccomp 系统调用控制模块

## memleak

内存泄漏检测模块

## oomkill

内存溢出检测模块

## profile

nginx lua 相关的 profile 模块
