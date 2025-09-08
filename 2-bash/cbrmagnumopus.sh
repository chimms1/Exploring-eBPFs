#!/bin/bash

echo "=> Compiling hbashmagnumopus.bpf.c"
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c hbashmagnumopus.bpf.c -o hbashmagnumopus.bpf.o  -D__BPF_TRACING__
# clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c hbashmagnumopus.bpf.c -o hbashmagnumopus.bpf.o -I/usr/include/x86_64-linux-gnu -I/usr/src/linux-headers-$(uname -r)/include -D__BPF_TRACING__

echo "=> Compiling loadermagnumopus.c"
gcc loadermagnumopus.c -o loadermagnumopus -lbpf -lelf -lz

echo "=> Building container"
docker build -t 2-hbash .

echo "=> Container built, running now"
docker run -it --privileged 2-hbash