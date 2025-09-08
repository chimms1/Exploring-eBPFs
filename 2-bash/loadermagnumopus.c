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
    struct bpf_program *trace_execve_prog, *tp_openat_enter_prog, *tp_read_exit_prog;
    struct bpf_link *trace_execve_link = NULL, *tp_openat_enter_link = NULL, *tp_read_exit_link = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open the compiled BPF object
    obj = bpf_object__open_file("hbashmagnumopus.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %ld\n", libbpf_get_error(obj));
        return 1;
    }

    // Load BPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    // Find and attach the raw tracepoint program

    // trace_execve
    trace_execve_prog = bpf_object__find_program_by_name(obj, "trace_execve");
    if (!trace_execve_prog) {
        fprintf(stderr, "Failed to find program trace_execve\n");
        bpf_object__close(obj);
        return 1;
    }
    trace_execve_link = bpf_program__attach(trace_execve_prog);
    if (libbpf_get_error(trace_execve_link)) {
        fprintf(stderr, "Failed to attach program: %ld\n", libbpf_get_error(trace_execve_link));
        trace_execve_link = NULL;
    } else {
        printf("Successfully attached raw tracepoint: raw_tracepoint/sys_enter trace_execve\n");
    }




    // tp_openat_enter
    tp_openat_enter_prog = bpf_object__find_program_by_name(obj, "tp_openat_enter");
    if (!tp_openat_enter_prog) {
        fprintf(stderr, "Failed to find program tp_openat_enter\n");
        bpf_object__close(obj);
        return 1;
    }
    tp_openat_enter_link = bpf_program__attach(tp_openat_enter_prog);
    if (libbpf_get_error(tp_openat_enter_link)) {
        fprintf(stderr, "Failed to attach program: %ld\n", libbpf_get_error(tp_openat_enter_link));
        tp_openat_enter_link = NULL;
    } else {
        printf("Successfully attached raw tracepoint: raw_tracepoint/sys_enter tp_openat_enter\n");
    }




    // 
    tp_read_exit_prog = bpf_object__find_program_by_name(obj, "tp_read_exit");
    if (!tp_read_exit_prog) {
        fprintf(stderr, "Failed to find program tp_read_exit\n");
        bpf_object__close(obj);
        return 1;
    }
    tp_read_exit_link = bpf_program__attach(tp_read_exit_prog);
    if (libbpf_get_error(tp_read_exit_link)) {
        fprintf(stderr, "Failed to attach program: %ld\n", libbpf_get_error(tp_read_exit_link));
        tp_read_exit_link = NULL;
    } else {
        printf("Successfully attached raw tracepoint: raw_tracepoint/sys_enter tp_read_exit\n");
    }



    printf("eBPF program loaded. Press Ctrl+C to exit.\n");



    while (!exiting)
        sleep(1);

    // Clean up
    if (trace_execve_link)
        bpf_link__destroy(trace_execve_link);
    // bpf_object__close(obj);

    if (tp_openat_enter_link)
        bpf_link__destroy(tp_openat_enter_link);
    // bpf_object__close(obj);

    if (tp_read_exit_link)
        bpf_link__destroy(tp_read_exit_link);
    bpf_object__close(obj);


    printf("\nUnloaded eBPF programs.\n");
    return 0;
}