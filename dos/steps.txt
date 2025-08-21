For falco container

# Default method given on their website
sudo docker run --rm -i -t --name falco --privileged  \
    -v /var/run/docker.sock:/host/var/run/docker.sock \
    -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro \
    -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro \
    falcosecurity/falco:latest




For attacker container

docker run --rm -it   --name ebpf-attacker  --pid=host   --privileged   -v /lib/modules:/lib/modules:ro   -v /usr/src:/usr/src:ro   ubuntu:22.04 bash

# Also worked with:
docker run -it --privileged killfalco:firstworking


apt install nano clang llvm libbpf-dev gcc make libelf-dev iproute2 linux-tools-common gcc-multilib


clang -O2 -target bpf -c kill_falco.bpf.c -o kill_falco.bpf.o
gcc loader.c -o loader -lbpf -lelf -lz


With Dockerfile:

docker build -t dosfalco .
docker run -it --privileged dosfalco
