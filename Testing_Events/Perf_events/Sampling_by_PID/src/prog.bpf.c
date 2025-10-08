// prog.bpf.c
#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct sample_t {
    u32 pid;
    u32 tid;
    u64 ip;
    u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} rb SEC(".maps");

SEC("perf_event")
int on_sample(struct bpf_perf_event_data *ctx)
{
    struct sample_t *s;
    u64 pid_tgid = bpf_get_current_pid_tgid();

    s = bpf_ringbuf_reserve(&rb, sizeof(*s), 0);
    if (!s)
        return 0;

    s->pid = pid_tgid >> 32;
    s->tid = (u32)pid_tgid;
    s->ts  = bpf_ktime_get_ns();

    // Captura del Program Counter (IP)
    s->ip = PT_REGS_IP(&ctx->regs);

    bpf_ringbuf_submit(s, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

