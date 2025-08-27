// block_rq_complete.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

// Estructura básica para block_rq_complete
struct trace_event_raw_block_rq_complete {
    char dev_name[32];
    unsigned long sector;
    unsigned int nr_sector;
    unsigned int bytes;
    int error;
};

SEC("tracepoint/block/block_rq_complete")
int handle_block_rq_complete(struct trace_event_raw_block_rq_complete *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("block_rq_complete: pid=%d dev=%s sector=%lu nr_sector=%u bytes=%u error=%d\n",
               pid, ctx->dev_name, ctx->sector, ctx->nr_sector, ctx->bytes, ctx->error);
    return 0;
}

