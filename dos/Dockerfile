# Use Ubuntu 22.04 as base image
FROM ubuntu:22.04

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
    zlib1g-dev

# Copy the source files into the container
COPY kill_falco.bpf.c /app/kill_falco.bpf.c
COPY loader.c /app/loader.c

# Run the build commands
RUN clang -O2 -target bpf -c kill_falco.bpf.c -o kill_falco.bpf.o \
    && gcc loader.c -o loader -lbpf -lelf -lz

# Set the default command
CMD ["/bin/bash"]

