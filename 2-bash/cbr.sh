#!/bin/bash

echo "=> Compiling hbash.bpf.c"
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c hbash.bpf.c -o hbash.bpf.o  -D__BPF_TRACING__

echo "=> Compiling loader.c"
gcc loader.c -o loader -lbpf -lelf -lz

echo "=> Building container"
docker build -t 2-hbash .

echo "=> Container built, running now"
docker run -it --privileged 2-hbash