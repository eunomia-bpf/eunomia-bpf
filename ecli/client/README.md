# ecli

## client operations

Start a program on endpoint:  
```console  
$ ./ecli client start ./execve.wasm
{"status":"Ok","tasks":[{"id":0}]}
```

List running program on endpoint:  
```console
$ ./ecli client list 
{"status":"Ok","tasks":[{"id":0,"name":"execve.wasm - WasmModule"}]}
```

Get log from endpoint:  
```console
$ ./ecli client log 0

[337348] fish -> /nix/store/jmc5ybg2zxfhgnq76vjnzj3sijrnzj40 export fish 
[337355] fish -> /etc/profiles/per-user/user/bin/starship prompt --terminal-width=93 --status=0 --pipestatus=0 --keymap=insert --cmd-duration=370 --jobs=0 
[337364] starship -> /etc/profiles/per-user/user/bin/git -C /home/user/Projects/eunomia-bpf/ecli/target --no-optional-locks status --porcelain=2 --branch 
[337365] starship -> /etc/profiles/per-user/user/bin/git -C /home/user/Projects/eunomia-bpf/ecli/target --no-optional-locks stash list 
[337372] git -> /nix/store/zq1zngyhbmgvyl53r5n0zd7mm1wj0jyp log --format=%gd: %gs -g --first-parent refs/stash -- 
[337373] git -> /nix/store/zq1zngyhbmgvyl53r5n0zd7mm1wj0jyp status --porcelain=2 
[337374] git -> /nix/store/zq1zngyhbmgvyl53r5n0zd7mm1wj0jyp status --porcelain=2 
[337375] fish -> /etc/profiles/per-user/riro/bin/starship prompt --right --terminal-width=93 --status=0 --pipestatus=0 --keymap=insert --cmd-duration=370 
```

Stop program:  

```console
$ ./ecli client stop 0
{"status":"execve.wasm terminated"}
```
```console
$ ./ecli client list
{"status":"Ok","tasks":[]}
```


```console
$ ./ecli client --help
Client operations

Usage: ecli client [OPTIONS] <COMMAND>

Commands:
  start  start an ebpf programs on endpoint
  stop   stop running tasks on endpoint with id
  log    show log of running task with id
  list   list the ebpf programs running on endpoint
  help   Print this message or the help of the given subcommand(s)

Options:
  -e, --endpoint <ENDPOINT>  endpoint [default: 127.0.0.1]
  -p, --port <PORT>          endpoint port [default: 8527]
  -s, --secure               transport with https
  -h, --help                 Print help
```
