// sys_enter_write.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    unsigned long fd = ctx->args[0];
    unsigned long count = ctx->args[2];
    bpf_printk("sys_enter_write: pid=%d fd=%lu count=%lu\n", pid, fd, count);
    return 0;
}

