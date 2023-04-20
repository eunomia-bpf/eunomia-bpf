# `ecli` / `ecli-client` 

## Acts as a http client

### Start a program on endpoint:  
```console  
$ ./ecli client start ./execve.wasm
1
```

### List running program on endpoint:  
```console
$ ./ecli client list 
1 bpf-program-1682439684 Running
2 bpf-program-1682439688 Running
```

### Get log from endpoint:  
```console
$ ./ecli client log 1

16:21:49 EXEC  sudo             52904   51113   /usr/bin/sudo
16:21:49 EXEC  ecli             52907   52906   target/debug/ecli
16:21:49 EXIT  ecli             52907   52906   [0] (419ms)
16:21:49 EXIT  sudo             52906   52904   [1]
16:21:49 EXIT  sudo             52904   51113   [0] (438ms)
```

### Stop program:  

```console
$ ./ecli client stop 1
```

```console
$ ./ecli client list
2 bpf-program-1682439688 Running
```

### Usage
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
```

## Acts as a native client
- Requires feature `native`
```console
$ ecli run ./ecli-lib/tests/bootstrap.wasm
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
16:24:34 EXIT  sleep            53566   53561   [0]
16:24:34 EXEC  sed              53567   53561   /usr/bin/sed
16:24:34 EXIT  sed              53567   53561   [0] (1ms)
16:24:34 EXEC  cat              53568   53561   /usr/bin/cat
16:24:34 EXIT  cat              53568   53561   [0] (0ms)
16:24:34 EXIT  cpuUsage.sh      53569   53561   [0]
```
