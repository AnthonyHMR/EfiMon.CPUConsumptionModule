// sys_enter_clone.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_clone")
int handle_sys_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    unsigned long flags = ctx->args[0];
    unsigned long stack = ctx->args[1];
    bpf_printk("sys_enter_clone: pid=%d flags=0x%lx stack=%lx\n", pid, flags, stack);
    return 0;
}

