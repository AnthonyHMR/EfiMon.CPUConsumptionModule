// sched_process_fork.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sched_process_fork {
    char parent_comm[16];
    int parent_pid;
    char child_comm[16];
    int child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    bpf_printk("sched_process_fork: parent=%s(%d) -> child=%s(%d)\n",
               ctx->parent_comm, ctx->parent_pid,
               ctx->child_comm, ctx->child_pid);
    return 0;
}

