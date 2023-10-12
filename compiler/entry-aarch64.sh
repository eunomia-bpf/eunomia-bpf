# Enable LIBCLANG_NOTHREADS so that we only need to load libclang*.so at runtime in the main thread
LIBCLANG_NOTHREADS=1 /ecc "$(ls /src/*.bpf.c)" "$(ls -h1 /src/*.h)" 
