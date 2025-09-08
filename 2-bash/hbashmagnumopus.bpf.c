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

// SEC("raw_tracepoint/sys_exit")
// int tp_openat_enter(struct bpf_raw_tracepoint_args *ctx)
// {
//     // 1) safely read ctx->args[0] into regs_ptr
//     unsigned long regs_ptr = 0;

//     if (bpf_probe_read(&regs_ptr, sizeof(regs_ptr), &ctx->args[0]) < 0)
//     {
//         return 0;
//     }

//     // regs_ptr now holds kernel address of struct pt_regs
//     // 2) read syscall number from pt_regs->orig_rax (kernel memory)
//     unsigned long syscall_nr = 0;

//     // Use offsetof to locate orig_rax inside pt_regs (x86_64)
//     if (bpf_probe_read(&syscall_nr, sizeof(syscall_nr), 
//                     (void *)(regs_ptr + offsetof(struct pt_regs, orig_rax))) < 0)
//     {
//         return 0;
//     }
    
//     if (syscall_nr != __NR_read || !is_bash_with_root(ctx))
//     {
//         return 0;
//     }

//     return 0;
// }

// SEC("raw_tracepoint/sys_exit")
// int tp_read_exit(struct bpf_raw_tracepoint_args *ctx)
// {
//     // 1) safely read ctx->args[0] into regs_ptr
//     unsigned long regs_ptr = 0;

//     if (bpf_probe_read(&regs_ptr, sizeof(regs_ptr), &ctx->args[0]) < 0)
//     {
//         return 0;
//     }

//     // regs_ptr now holds kernel address of struct pt_regs
//     // 2) read syscall number from pt_regs->orig_rax (kernel memory)
//     unsigned long syscall_nr = 0;

//     // Use offsetof to locate orig_rax inside pt_regs (x86_64)
//     if (bpf_probe_read(&syscall_nr, sizeof(syscall_nr), 
//                     (void *)(regs_ptr + offsetof(struct pt_regs, orig_rax))) < 0)
//     {
//         return 0;
//     }
    
//     if (syscall_nr != __NR_read || !is_bash_with_root(ctx))
//     {
//         return 0;
//     }

//     return 0;
// }













// // hbash.bpf.c
// // Tracks execve argv[1], watches openat for matching filename, records returned fd on sys_exit_openat,
// // and when read(fd) is called, prints content read from that fd (bounded).
// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <stdint.h>

// #define MAX_BUF 128
// #define MAX_ENTRIES 10240

// struct trace_event_raw_sys_enter {
//     unsigned long long pad;
//     unsigned long long args[6];
// };

// struct trace_event_raw_sys_exit {
//     unsigned long long pad;
//     long ret;
// };

// /* key for fd->filename map */
// struct pid_fd_key {
//     __u32 pid;
//     int fd;
// };

// /* =========== Maps =========== */
// /* exec_args_map: pid -> argv[1] (script filename) */
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u32);
//     __type(value, char[MAX_BUF]);
//     __uint(max_entries, MAX_ENTRIES);
// } exec_args_map SEC(".maps");

// /* open_tmp_map: temporary store for matching openat filename during sys_enter_openat
//    keyed by pid -> filename. Will be consumed in sys_exit_openat. */
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u32);
//     __type(value, char[MAX_BUF]);
//     __uint(max_entries, MAX_ENTRIES);
// } open_tmp_map SEC(".maps");

// /* fd_file_map: (pid, fd) -> filename (persisted after openat returns) */
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, struct pid_fd_key);
//     __type(value, char[MAX_BUF]);
//     __uint(max_entries, MAX_ENTRIES);
// } fd_file_map SEC(".maps");

// /* =========== Helpers =========== */
// /* Bounded, verifier-friendly string equality (returns 1 if equal, 0 otherwise) */
// static __inline int str_eq(const char *a, const char *b, int maxlen)
// {
//     int i;
//     #pragma unroll
//     for (i = 0; i < MAX_BUF; i++) {
//         char ca = a[i];
//         char cb = b[i];
//         if (ca == '\0' && cb == '\0')
//             return 1;
//         if (ca != cb)
//             return 0;
//     }
//     return 0;
// }

// /* =========== Tracepoints =========== */

// /* execve enter: args[0] = filename, args[1] = argv */
// /* We capture argv[1] (if present) and store in exec_args_map keyed by pid. */
// SEC("tracepoint/syscalls/sys_enter_execve")
// int trace_execve(struct trace_event_raw_sys_enter *ctx)
// {
//     unsigned long argv_ptr = (unsigned long)ctx->args[1];
//     if (!argv_ptr)
//         return 0;

//     /* read argv[1] pointer: argv is array of pointers, argv[1] = argv + 1 */
//     unsigned long user_arg1_addr = argv_ptr + sizeof(void *);
//     const char *arg1_ptr = NULL;
//     if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), (const void *)user_arg1_addr) != 0)
//         return 0;

//     if (!arg1_ptr)
//         return 0;

//     char filename[MAX_BUF] = {};
//     if (bpf_probe_read_user_str(&filename, sizeof(filename), (const void *)arg1_ptr) <= 0)
//         return 0;

//     __u32 pid = (__u32)bpf_get_current_pid_tgid();
//     /* store argv[1] (script filename) */
//     bpf_map_update_elem(&exec_args_map, &pid, &filename, BPF_ANY);

//     bpf_printk("execve: pid=%d argv1=%s\n", pid, filename);
//     return 0;
// }

// /* openat enter: args[0]=dfd, args[1]=filename
//    We read filename and compare to stored exec argv[1]. If matches, stash filename in open_tmp_map for pid. */
// SEC("tracepoint/syscalls/sys_enter_openat")
// int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
// {
//     const char *user_fname_ptr = (const char *)ctx->args[1];
//     if (!user_fname_ptr)
//         return 0;

//     char fname[MAX_BUF] = {};
//     if (bpf_probe_read_user_str(&fname, sizeof(fname), (const void *)user_fname_ptr) <= 0)
//         return 0;

//     __u32 pid = (__u32)bpf_get_current_pid_tgid();

//     /* check exec_args_map for this pid */
//     char *exec_fname = bpf_map_lookup_elem(&exec_args_map, &pid);
//     if (!exec_fname)
//         return 0;

//     /* compare: if equal, keep in tmp map to record fd on exit */
//     if (str_eq(exec_fname, fname, MAX_BUF)) {
//         /* store the filename temporarily for this pid */
//         bpf_map_update_elem(&open_tmp_map, &pid, &fname, BPF_ANY);
//         bpf_printk("openat_enter: pid=%d matched exec filename=%s\n", pid, fname);
//     }

//     return 0;
// }

// /* openat exit: ctx->ret has returned fd (or negative error)
//    If open_tmp_map has a filename for this pid and ret >= 0, store (pid, fd) -> filename in fd_file_map. */
// SEC("tracepoint/syscalls/sys_exit_openat")
// int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
// {
//     long ret = ctx->ret;
//     __u32 pid = (__u32)bpf_get_current_pid_tgid();

//     /* see if we had a matching filename pending */
//     char *tmp_fname = bpf_map_lookup_elem(&open_tmp_map, &pid);
//     if (!tmp_fname)
//         return 0;

//     /* remove temp entry (we will either store in fd map or drop) */
//     bpf_map_delete_elem(&open_tmp_map, &pid);

//     if (ret < 0)
//         return 0; /* open failed */

//     struct pid_fd_key k = {};
//     k.pid = pid;
//     k.fd = (int)ret;

//     /* store filename keyed by (pid, fd) */
//     if (bpf_map_update_elem(&fd_file_map, &k, tmp_fname, BPF_ANY) != 0) {
//         /* ignore failure */
//     } else {
//         bpf_printk("openat_exit: pid=%d fd=%d filename=%s\n", pid, k.fd, tmp_fname);
//     }

//     return 0;
// }

// /* read enter: args[0]=fd, args[1]=buf, args[2]=count
//    Look up (pid, fd) in fd_file_map and print content (bounded). */
// SEC("tracepoint/syscalls/sys_enter_read")
// int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
// {
//     int fd = (int)ctx->args[0];
//     const void *user_buf = (const void *)ctx->args[1];
//     // size_t count = (size_t)ctx->args[2];

//     __u32 pid = (__u32)bpf_get_current_pid_tgid();

//     struct pid_fd_key k = {};
//     k.pid = pid;
//     k.fd = fd;

//     char *fname = bpf_map_lookup_elem(&fd_file_map, &k);
//     if (!fname)
//         return 0;

//     /* read a bounded amount from the user buffer (MAX_BUF-1) */
//     char buf[MAX_BUF] = {};
//     if (bpf_probe_read_user(&buf, sizeof(buf) - 1, user_buf) != 0)
//         return 0;

//     bpf_printk("read: pid=%d fd=%d file=%s content=%s\n", pid, fd, fname, buf);
//     return 0;
// }

// /* optional: a cleanup helper not strictly necessary (could be removed) */

// /* license */
// char LICENSE[] SEC("license") = "GPL";
