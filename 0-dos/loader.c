#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <unistd.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    obj = bpf_object__open_file("kill_falco.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "kill_falco");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        return 1;
    }

    link = bpf_program__attach(prog); // works for kprobe
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Attach failed\n");
        return 1;
    }

    printf("Kill-Falco eBPF loaded. Press Ctrl+C to exit.\n");
    while (1) sleep(1);

    return 0;
}

