---
title: ecli server
catagories: ['ecli']
---

# ecli server

You can use server to manager and dynamically install eBPF programs.

## install

For example, on Ubuntu:

```sh
# download the preview build server
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli-server-ubuntu-latest.tar.gz
tar -xzf ecli-server-ubuntu-latest.tar.gz && chmod +x ./ecli-server
# download the ecli
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
```

## usage

start the server:

```console
$ sudo ./ecli-server
[2023-08-08 02:02:03.864009 +08:00] INFO [server/src/main.rs:95] Serving at 127.0.0.1:8527
```

use the ecli to control the remote server and manage multiple eBPF programs:

```console
$ ./ecli client --help
Client operations

Usage: ecli client [OPTIONS] <COMMAND>

Commands:
  start   Start an ebpf program on the specified endpoint
  stop    Stop running a task on the specified endpoint
  log     Fetch logs of the given task
  pause   Pause the task
  resume  Resume the task
  list    List tasks on the server
  help    Print this message or the help of the given subcommand(s)

Options:
  -e, --endpoint <ENDPOINT>  API endpoint [default: http://127.0.0.1:8527]
  -h, --help                 Print help

# you can download sigsnoop.json from https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/package.json
$ ./ecli client start sigsnoop.json # start the program
1
$ ./ecli client log 1 # get the log of the program
TIME     PID    TPID   SIG    RET    COMM   
02:05:58  79725 78132  17     0      bash
02:05:59  77325 77297  0      0      node
02:05:59  77297 8042   0      0      node
02:05:59  77297 8042   0      0      node
02:05:59  79727 79726  17     0      which
02:05:59  79726 8084   17     0      sh
02:05:59  79731 79730  17     0      which
$ ./ecli client start sigsnoop.json # start another program
2
$ ./ecli client list # list all running programs
1 bpf-program-1691431558 Running
2 bpf-program-1691431757 Running
$ ./ecli client stop 1 # stop the program 1
$ ./ecli client list
2 bpf-program-1691431757 Running
$ ./ecli client stop 2 # stop the program 2
$ ./ecli client list # no program is running
```

## API document

For the http api, please refer to [openapi.yaml](../../../ecli/apis.yaml).

You can also use curl to access the ecli server, for example:

```console
$ curl http://127.0.0.1:8527/task # list all running tasks
{"tasks":[{"status":"running","id":3,"name":"bpf-program-1691432359"}]}
$ curl -X POST   -H "Content-Type: application/json"   -d '{
    "id": 3,
    "log_cursor": 0,
    "maximum_count": 100
  }'  http://127.0.0.1:8527/log # get the log of the task 3
[{"cursor":0,"log":{"log":"TIME     PID    TPID   SIG    RET    COMM   ","timestamp":1691432359,"log_type":"plain"}},{"cursor":1,"log":{"log":"02:19:19  81241 
....
,{"cursor":99,"log":{"log":"02:19:28  80808 77297  0      0      node","timestamp":1691432368,"log_type":"plain"}}]
```
