# ecli server

start a server:

```console
$ sudo ecli/build/bin/Release/ecli server
[2022-08-22 22:43:36.201] [info] start server mode...
[2022-08-22 22:43:36.201] [info] start eunomia...
[2022-08-22 22:43:36.201] [info] eunomia server start at port 8527
```

use client to communicate with the server:

```console
$ sudo ./ecli client list
200 :["status","ok","list",[]]

$ sudo ./ecli client start https://eunomia-bpf.github.io/ebpm-template/package.json
2022-08-22 22:44:37 URL:https://eunomia-bpf.github.io/ebpm-template/package.json [42181] -> "/tmp/ebpm/package.json" [1]
200 :["status","ok","id",1]

$ sudo ./ecli client list
200 :["status","ok","list",[[1,"execsnoop"]]]

$ sudo ./ecli client stop 1
200 :["status","ok"]

$ sudo ./ecli client list
200 :["status","ok","list",[]]
```
