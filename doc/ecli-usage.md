## examples

run an pre-compiled ebpf program:

```console
$ sudo ./ecli run https://gitee.com/yunwei37/eunomia-bpf/raw/master/bpftools/examples/package.json
$ sudo ./ecli run https://github.com/eunomia-bpf/eunomia-bpf/raw/master/bpftools/examples/package.json
$ sudo ./ecli run bpftools/examples/package.json
```

start a server:

```console
$ sudo ecli/build/bin/Release/eunomia server
[2022-08-22 22:43:36.201] [info] start server mode...
[2022-08-22 22:43:36.201] [info] start eunomia...
[2022-08-22 22:43:36.201] [info] eunomia server start at port 8527
```

use client to communicate with the server:

```console
$ sudo ./ecli client list
200 :["status","ok","list",[]]

$ sudo ./ecli client start https://gitee.com/yunwei37/eunomia-bpf/raw/master/bpftools/examples/package.json
2022-08-22 22:44:37 URL:https://gitee.com/yunwei37/eunomia-bpf/raw/master/bpftools/examples/package.json [42181] -> "/tmp/ebpm/package.json" [1]
200 :["status","ok","id",1]

$ sudo ./ecli client list
200 :["status","ok","list",[[1,"execsnoop"]]]

$ sudo ./ecli client stop 1
200 :["status","ok"]

$ sudo ./ecli client list
200 :["status","ok","list",[]]
```

## help info

```console
SYNOPSIS
        ecli/build/bin/Release/eunomia [--log-level <log level>] client list [--endpoint <server
            endpoint>]

        ecli/build/bin/Release/eunomia [--log-level <log level>] client start <url> [<extra
            args>]... [--endpoint <server endpoint>]

        ecli/build/bin/Release/eunomia [--log-level <log level>] client stop <stop id> [--endpoint
            <server endpoint>]

        ecli/build/bin/Release/eunomia [--log-level <log level>] run <url> [<extra args>]...
        ecli/build/bin/Release/eunomia [--log-level <log level>] server [--config <config file>]
        ecli/build/bin/Release/eunomia [--log-level <log level>] help

OPTIONS
        --log-level <log level>
                    The log level for the eunomia cli, can be debug, info, warn, error

        use client to control the ebpf programs in remote server
            list    list the ebpf programs running on endpoint
            start   start an ebpf programs on endpoint
            <url>   The url to get the ebpf program, can be file path or url
            <extra args>...
                    Some extra args provided to the ebpf program

            stop    stop an ebpf programs on endpoint
            <stop id>
                    The id of the ebpf program to stop in sercer

            --endpoint <server endpoint>
                    The endpoint of server to connect to

        run a ebpf program
            <url>   The url to get the ebpf program, can be file path or url
            <extra args>...
                    Some extra args provided to the ebpf program

        start a server to control the ebpf programs
            --config <config file>
                    The json file stores the config data
```