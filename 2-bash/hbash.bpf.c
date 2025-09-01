// hbash.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

#include <stdint.h>

#include <linux/ptrace.h>
#include <asm/unistd_64.h>


// #include <linux/syscalls.h>

#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "GPL";


// The key will be 0, and the value will be the file descriptor
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} fd_map SEC(".maps");

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

void save_target_bash_fd(long ret_fd) 
{
    // Store the file descriptor in the map
    int key = 0;
    long ret = bpf_map_update_elem(&fd_map, &key, &ret_fd, BPF_ANY);
    
    if (ret != 0) 
    {
        bpf_printk("Failed to update map: %d\n", ret);
    }
}


SEC("raw_tracepoint/sys_exit")
int tp_exit(struct bpf_raw_tracepoint_args *ctx)
{
    // long syscall_nr = ctx->args[1];

    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    long ret = (long)ctx->args[1];

    
    // Get the syscall number from the regs struct
    long syscall_nr = BPF_CORE_READ(regs, orig_rax);

    // Check for openat and bash with root privileges
    // if (syscall_nr == __NR_openat && is_bash_with_root(ctx)) {

    if (is_bash_with_root(ctx)) {
        
        // long ret_fd = ctx->args[0];
        int fd = (int)ret;

        bpf_printk("from tp_exit=> Found bash in root, file descriptor=> %ld syscall_nr=> %d\n", ret,syscall_nr);

        // Ensure the file descriptor is valid (>= 0)
        if (fd >= 0) 
        {

            save_target_bash_fd(fd);
        }
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