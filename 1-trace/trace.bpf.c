// trace.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "GPL";

SEC("raw_tracepoint/sys_enter")
int trace_processes(struct bpf_raw_tracepoint_args *ctx)
{
    char comm[TASK_COMM_LEN];
    int pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_printk("PID: %d, COMM: %s\n", pid, comm);

    // for specific processes
    // // Compare first 4 chars with
    // if (__builtin_memcmp(comm, "bash", 4) == 0) {
    //     bpf_printk("Matched! PID: %d, COMM: %s\n", pid, comm);
    // }


    return 0;
}
