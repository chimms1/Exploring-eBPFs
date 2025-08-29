// trace.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

#include <stdint.h>

#include <linux/ptrace.h>

#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "GPL";

int is_bash_with_root(struct pt_regs *ctx)
{
    char comm[TASK_COMM_LEN];
    
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // check if bash
    if(__builtin_memcmp(comm, "bash", 4) == 0) {
        
        // Get the current user and group IDs
        unsigned long long uid_gid = bpf_get_current_uid_gid();
        
        // UID is in lower 32 bits
        uint32_t uid = (uint32_t)uid_gid;
        
        bpf_printk("Bash found, COMM=> %s uid=> %u\n", comm, uid);
        
        // if bash is in root
        if(uid==0)
        {
            bpf_printk("\nROOOOOOOOOT\n");
            return 1;
        }
    }
    return 0;
}

void save_target_bash_fd(struct pt_regs *ctx) 
{
    int fd = PT_REGS_RC(ctx);

    bpf_printk("fd is %d\n",fd);
}


SEC("raw_tracepoint/sys_exit")
int tp_exit(struct bpf_raw_tracepoint_args *ctx)
{
    
    if(is_bash_with_root(ctx))
    {
        bpf_printk("Found bash in root");
    }

    return 0;
}

int should_modify_return(struct pt_regs *ctx)
{
    return 1;
}

SEC("kretprobe/__x64_sys_read")
int modify_read_size(struct pt_regs *ctx)
{
    if(should_modify_return(ctx))
    {
        // logic to be implemented
    }

    return 0;
}