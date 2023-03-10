# ecli docker

bpf 运行时需要有Linux内核相关支持，docker 中的内核共享的宿主机的内核，因此使用docker运行bpf程序时需要使用以下命令为容器赋予权限和相关内核支持。

此处参考https://github.com/iovisor/bpftrace/blob/master/INSTALL.md#kernel-headers-install

```shell
$ docker run -ti -v /usr/src:/usr/src:ro \
       -v /lib/modules/:/lib/modules:ro \
       -v /sys/kernel/debug/:/sys/kernel/debug:rw \
       -v /home/admin/my:/root/my \ //挂载本机目录到容器的/root/my路径下
       --net=host --pid=host --privileged \
       ecli:1.0.1
```

## dockerfile ubuntu

dockerfile的基础镜像是Ubuntu，国内使用时因为有墙的存在，所以需要对Linux进行换源。sources.list如下：

```shell
deb http://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse
#deb-src http://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse
#deb-src http://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse
#deb-src http://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-proposed main restricted universe multiverse
#deb-src http://mirrors.aliyun.com/ubuntu/ jammy-proposed main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse
#deb-src http://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse
```

dockerfile中的具体内容如下

```shell
FROM ubuntu:latest

ENV UBUNTU_SOURCE /etc/apt

COPY ./ /root

WORKDIR /root

ADD sources.list $UBUNTU_SOURCE/

RUN apt-get update && \
    apt-get -y install gcc libelf-dev

#CMD ./ecli run /root/my/package.json
CMD ["/bin/bash"]

```

ubuntu.dockerfile构建时，同一级目录下的文件如下

![image-20220905232754264](images\image-20220905232754264.png)

ecli可执行文件  sources.list Dockerfile这三个文件缺一不可，other文件可忽略。docker容器中wget无法连接外部网络，因此需要在docker构建时将ecli放入镜像中。使用镜像时只要挂载的本机目录中有package.json文件即可。

## docker alpine

```shell
FROM alpine:latest

COPY ./ /root

WORKDIR /root

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk update && \
    apk install gcc libelf gcompat

#CMD ./ecli run /root/my/package.json
```

alpine.dockerfile构建镜像时，同一级目录下必须有ecli可执行文件。
目前alpine.dockerfile仍存在以下问题

### docker build

dockerfile构建时使用如下命令

```shell
sudo docker build -t ecli:1.0.1 .
```

### 参考文档

bpftrace 官方说明（如何让bpf程序在docker中运行）

https://github.com/iovisor/bpftrace/blob/master/INSTALL.md#kernel-headers-install

如何在mac中运行带有bpf运行环境的docker

https://petermalmgren.com/docker-mac-bpf-perf/