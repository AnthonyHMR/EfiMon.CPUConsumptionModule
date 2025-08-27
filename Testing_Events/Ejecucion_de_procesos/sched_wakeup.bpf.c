// sched_wakeup.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sched_wakeup {
    char comm[16];
    int pid;
    int prio;
    int success;
};

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup *ctx) {
    bpf_printk("sched_wakeup: comm=%s pid=%d prio=%d success=%d\n",
               ctx->comm, ctx->pid, ctx->prio, ctx->success);
    return 0;
}

