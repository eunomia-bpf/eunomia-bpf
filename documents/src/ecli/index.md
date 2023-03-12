# 命令行工具

## help info

```console
SYNOPSIS
        ecli/build/bin/Release/ecli [--log-level <log level>] client list [--endpoint <server
            endpoint>]

        ecli/build/bin/Release/ecli [--log-level <log level>] client start <url> [<extra
            args>]... [--endpoint <server endpoint>]

        ecli/build/bin/Release/ecli [--log-level <log level>] client stop <stop id> [--endpoint
            <server endpoint>]

        ecli/build/bin/Release/ecli [--log-level <log level>] run <url> [<extra args>]...
        ecli/build/bin/Release/ecli [--log-level <log level>] server [--config <config file>]
        ecli/build/bin/Release/ecli [--log-level <log level>] help

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
