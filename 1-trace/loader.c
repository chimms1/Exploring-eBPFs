// loader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t exiting = 0;

void sig_handler(int sig)
{
    exiting = 1;
}

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file("trace.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "trace_processes");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        return 1;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Attach failed\n");
        return 1;
    }

    printf("trace_processes eBPF loaded. Press Ctrl+C to exit.\n");
    while (!exiting)
        sleep(1);

    bpf_link__destroy(link);
    bpf_object__close(obj);
    printf("Unloaded eBPF program.\n");
    return 0;
}
