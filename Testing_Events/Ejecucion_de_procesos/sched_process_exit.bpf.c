// sched_process_exit.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sched_process_exit {
    char comm[16];
    int pid;
};

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    bpf_printk("sched_process_exit: comm=%s pid=%d\n",
               ctx->comm, ctx->pid);
    return 0;
}

