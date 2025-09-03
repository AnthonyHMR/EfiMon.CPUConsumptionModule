// sys_exit_write.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sys_exit {
    unsigned long long unused;
    long id;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_write")
int handle_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    long ret = ctx->ret;
    bpf_printk("sys_exit_write: pid=%d ret=%ld\n", pid, ret);
    return 0;
}

