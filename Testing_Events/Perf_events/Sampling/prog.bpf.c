// prog.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct sample_t {
    u32 pid;
    u32 tid;
    u64 ip;
    u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

SEC("perf_event")
int on_sample(struct bpf_perf_event_data *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sample_t *s;

    s = bpf_ringbuf_reserve(&rb, sizeof(*s), 0);
    if (!s)
        return 0;

    s->pid = pid_tgid >> 32;
    s->tid = (u32)pid_tgid;
#ifdef __x86_64__
    s->ip  = PT_REGS_IP(&ctx->regs); // Instruction Pointer (PC)
#else
    s->ip  = 0; // Ajustar para otra arquitectura
#endif
    s->ts  = bpf_ktime_get_ns();

    bpf_ringbuf_submit(s, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

