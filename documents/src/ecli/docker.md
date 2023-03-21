# ecli docker

bpf 运行时需要有Linux内核相关支持，docker 中的内核共享的宿主机的内核，因此使用docker运行bpf程序时需要使用以下命令为容器赋予权限和相关内核支持。

此处参考 https://github.com/iovisor/bpftrace/blob/master/INSTALL.md#kernel-headers-install

```shell
$ docker run -ti -v /usr/src:/usr/src:ro \
       -v /lib/modules/:/lib/modules:ro \
       -v /sys/kernel/debug/:/sys/kernel/debug:rw \
       -v /home/admin/my:/root/my \ //挂载本机目录到容器的/root/my路径下
       --net=host --pid=host --privileged \
       ecli:1.0.1
```
