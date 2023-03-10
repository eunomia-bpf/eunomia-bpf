# common problem

if you get a error like `/usr/lib/x86_64-linux-gnu/libstdc++.so.6: version GLIBCXX_3.4.29 not found` on old version kernels,

try:

```console
sudo apt-get upgrade libstdc++6
```

see https://stackoverflow.com/questions/65349875/where-can-i-find-glibcxx-3-4-29