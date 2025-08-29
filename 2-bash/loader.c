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
    struct bpf_program *tp_prog, *kret_prog;
    struct bpf_link *tp_link = NULL, *kret_link = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open the compiled BPF object (update name if needed)
    obj = bpf_object__open_file("hbash.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %ld\n", libbpf_get_error(obj));
        return 1;
    }

    // Load BPF programs into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    // Attach raw tracepoint: tp_exit
    tp_prog = bpf_object__find_program_by_name(obj, "tp_exit");
    if (!tp_prog) {
        fprintf(stderr, "Failed to find program tp_exit\n");
        bpf_object__close(obj);
        return 1;
    }

    tp_link = bpf_program__attach(tp_prog);
    if (libbpf_get_error(tp_link)) {
        fprintf(stderr, "Failed to attach tp_exit: %ld\n", libbpf_get_error(tp_link));
        tp_link = NULL;
    } else {
        printf("Attached raw tracepoint: tp_exit\n");
    }

    // Attach kretprobe: modify_read_size
    kret_prog = bpf_object__find_program_by_name(obj, "modify_read_size");
    if (!kret_prog) {
        fprintf(stderr, "Failed to find program modify_read_size\n");
    } else {
        kret_link = bpf_program__attach(kret_prog);
        if (libbpf_get_error(kret_link)) {
            fprintf(stderr, "Failed to attach modify_read_size: %ld\n", libbpf_get_error(kret_link));
            kret_link = NULL;
        } else {
            printf("Attached kretprobe: modify_read_size\n");
        }
    }

    printf("eBPF programs loaded. Press Ctrl+C to exit.\n");

    while (!exiting)
        sleep(1);

    // Clean up
    if (tp_link)
        bpf_link__destroy(tp_link);
    if (kret_link)
        bpf_link__destroy(kret_link);
    bpf_object__close(obj);

    printf("Unloaded eBPF programs.\n");
    return 0;
}
