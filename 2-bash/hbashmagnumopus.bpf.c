// hbash.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

#include <stdint.h>

#include <linux/ptrace.h>
#include <asm/unistd_64.h>

#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/types.h>
#include <linux/string.h>

#define MAX_BUF 128

// Declare maps for storing the command arguments and file names
BPF_HASH(exec_args_map, u32, char[MAX_BUF]);   // For storing script file names from execve
BPF_HASH(file_names, u32, char[MAX_BUF]);      // For storing file names from openat

// This function is attached to the 'execve' syscall
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct pt_regs *ctx) {
    char filename[MAX_BUF];
    u32 pid = bpf_get_current_pid_tgid();

    // Get the pointer to argv (second argument to execve, which is an array of arguments)
    char **argv = (char **)PT_REGS_PARM2(ctx);

    // Check if argv[1] is non-NULL and capture the filename (usually the second argument is the script filename)
    if (argv && argv[1]) {
        // Copy the filename (argv[1]) to our buffer
        bpf_probe_read_user_str(&filename, sizeof(filename), argv[1]);

        // Save the filename in the exec_args_map with the PID as the key
        exec_args_map.update(&pid, &filename);

        // Optionally print the filename of the script being executed
        bpf_trace_printk("Executing shell script: %s\n", filename);
    }

    return 0;
}

// This function is attached to the 'openat' syscall
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct pt_regs *ctx) {
    // Get the filename argument (rsi) from the 'openat' syscall
    char filename[MAX_BUF];
    u32 pid = bpf_get_current_pid_tgid();

    // Read the filename from user space
    bpf_probe_read_user_str(&filename, sizeof(filename), (void *)PT_REGS_PARM2(ctx));

    // Look up the filename from the exec_args_map using the PID
    char *exec_filename = exec_args_map.lookup(&pid);
    if (exec_filename) {
        // If the current filename matches the one captured from execve
        if (strstr(filename, exec_filename) != NULL) {
            // Save the filename in the file_names map with the PID as the key
            file_names.update(&pid, &filename);
        }
    }

    return 0;
}

// This function is attached to the 'read' syscall
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read(struct pt_regs *ctx) {
    // Get file descriptor (rdi)
    int fd = PT_REGS_PARM1(ctx);
    
    // Check if this is the file descriptor for the file opened by the execve program
    char filename[MAX_BUF];
    u32 pid = bpf_get_current_pid_tgid();
    
    // Get the filename from the map (we saved it during 'openat' call)
    if (file_names.lookup(&pid)) {
        bpf_probe_read_user_str(&filename, sizeof(filename), (void *)file_names.lookup(&pid));

        // Check if the file descriptor matches the file opened by the script (usually fd == 3)
        if (fd == 3) {  // File descriptor for the script is usually 3
            // Now we can capture the content of the file read operation
            char buf[MAX_BUF];
            bpf_probe_read_user(&buf, sizeof(buf), (void *)PT_REGS_PARM2(ctx));

            // Here we can process the buffer to inspect the content of the file
            bpf_trace_printk("Reading from file: %s, Content: %s\n", filename, buf);
        }
    }

    return 0;
}
