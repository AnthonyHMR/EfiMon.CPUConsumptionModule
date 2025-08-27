// block_rq_issue.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

// Estructura básica para block_rq_issue
struct trace_event_raw_block_rq_issue {
    char dev_name[32];
    unsigned long sector;
    unsigned int nr_sector;
    unsigned int bytes;
    unsigned int rwbs;
};

SEC("tracepoint/block/block_rq_issue")
int handle_block_rq_issue(struct trace_event_raw_block_rq_issue *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("block_rq_issue: pid=%d dev=%s sector=%lu nr_sector=%u bytes=%u rwbs=%u\n",
               pid, ctx->dev_name, ctx->sector, ctx->nr_sector, ctx->bytes, ctx->rwbs);
    return 0;
}

