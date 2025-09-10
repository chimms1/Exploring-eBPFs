# Use Ubuntu 22.04 as base image
FROM ubuntu:24.04

# Set the working directory in the container
WORKDIR /app

# Install necessary dependencies
RUN apt update && apt install -y \
    nano \
    clang \
    llvm \
    libbpf-dev \
    gcc \
    make \
    libelf-dev \
    iproute2 \
    linux-tools-common \
    gcc-multilib \
    zlib1g-dev \
    libbpf1

COPY infostealmagnumopus.bpf.o /app/infostealmagnumopus.bpf.o
COPY loadermagnumopus /app/loadermagnumopus
# # Copy the source files into the container
# COPY hbash.bpf.c /app/hbash.bpf.c
# COPY loader.c /app/loader.c

# # Run the build commands
# # RUN clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c hbash.bpf.c -o hbash.bpf.o -g -O2 -target bpf -D__BPF_TRACING__ \
# #     && gcc loader.c -o loader -lbpf -lelf -lz
# RUN clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c hbash.bpf.c -o hbash.bpf.o \
#     -I/usr/include/x86_64-linux-gnu -I/usr/src/linux-headers-$(uname -r)/include \
#     -D__BPF_TRACING__
# RUN gcc loader.c -o loader -lbpf -lelf -lz
# Set the default command
CMD ["/bin/bash"]

