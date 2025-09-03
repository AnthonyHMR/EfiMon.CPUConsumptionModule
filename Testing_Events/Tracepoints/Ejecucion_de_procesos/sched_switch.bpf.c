// sched_switch.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sched_switch {
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    unsigned long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    bpf_printk("sched_switch: %s(%d) -> %s(%d)\n",
               ctx->prev_comm, ctx->prev_pid,
               ctx->next_comm, ctx->next_pid);
    return 0;
}

