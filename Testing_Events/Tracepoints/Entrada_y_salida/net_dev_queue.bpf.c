// net_dev_queue.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

// tracepoint net_dev_queue
struct trace_event_raw_net_dev_queue {
    char name[16];
    unsigned int len;
};

SEC("tracepoint/net/net_dev_queue")
int handle_net_dev_queue(struct trace_event_raw_net_dev_queue *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("net_dev_queue: pid=%d dev=%s len=%u\n",
               pid, ctx->name, ctx->len);
    return 0;
}

