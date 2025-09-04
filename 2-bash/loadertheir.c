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
    struct bpf_program *sys_enter_prog, *sys_exit_prog;
    struct bpf_link *sys_enter_link = NULL, *sys_exit_link = NULL;
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

    // Attach raw tracepoint: sys_enter
    sys_enter_prog = bpf_object__find_program_by_name(obj, "raw_tp_sys_enter");
    if (!sys_enter_prog) {
        fprintf(stderr, "Failed to find program raw_tp_sys_enter\n");
        bpf_object__close(obj);
        return 1;
    }

    sys_enter_link = bpf_program__attach(sys_enter_prog);
    if (libbpf_get_error(sys_enter_link)) {
        fprintf(stderr, "Failed to attach raw_tp_sys_enter: %ld\n", libbpf_get_error(sys_enter_link));
        sys_enter_link = NULL;
    } else {
        printf("Attached raw tracepoint: sys_enter\n");
    }

    // Attach raw tracepoint: sys_exit
    sys_exit_prog = bpf_object__find_program_by_name(obj, "raw_tp_sys_exit");
    if (!sys_exit_prog) {
        fprintf(stderr, "Failed to find program raw_tp_sys_exit\n");
    } else {
        sys_exit_link = bpf_program__attach(sys_exit_prog);
        if (libbpf_get_error(sys_exit_link)) {
            fprintf(stderr, "Failed to attach raw_tp_sys_exit: %ld\n", libbpf_get_error(sys_exit_link));
            sys_exit_link = NULL;
        } else {
            printf("Attached raw tracepoint: sys_exit\n");
        }
    }

    printf("eBPF programs loaded. Press Ctrl+C to exit.\n");

    while (!exiting)
        sleep(1);

    // Clean up
    if (sys_enter_link)
        bpf_link__destroy(sys_enter_link);
    if (sys_exit_link)
        bpf_link__destroy(sys_exit_link);
    bpf_object__close(obj);

    printf("Unloaded eBPF programs.\n");
    return 0;
}
