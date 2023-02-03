# examples

## build

```sh
make
```

## run

```console
$ sudo wasm-runtime/build/bin/Release/wasm-bpf bootstrap.wasm
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
18:57:58 EXEC  sed              74911   74910   /usr/bin/sed
18:57:58 EXIT  sed              74911   74910   [0] (2ms)
18:57:58 EXIT  cat              74912   74910   [0] (0ms)
18:57:58 EXEC  cat              74913   74910   /usr/bin/cat
18:57:59 EXIT  cat              74913   74910   [0] (0ms)
18:57:59 EXEC  cat              74914   74910   /usr/bin/cat
18:57:59 EXIT  cat              74914   74910   [0] (0ms)
18:57:59 EXEC  cat              74915   74910   /usr/bin/cat
18:57:59 EXIT  cat              74915   74910   [0] (1ms)
18:57:59 EXEC  sleep            74916   74910   /usr/bin/sleep
```