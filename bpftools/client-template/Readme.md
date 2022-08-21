# hot update single link & prog libbpf ebpf code template

```
make
```

## examples

- bpftools/client-template/client.bpf.c: file open
- bpftools/client-template/client.example1.bpf.c: process exec
- bpftools/client-template/client.example2.bpf.c: process exit

## usage

```bash
# generate json request
./client > update.json

# start ebpf tracker
./client start

# list all running trackers
./client list

# stop ebpf tracker id 1
./client stop 1
```