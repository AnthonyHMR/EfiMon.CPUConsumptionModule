// prog.bpf.c
#include "vmlinux.h"
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
    __uint(max_entries, 1 << 24); // 16 MB
} rb SEC(".maps");

SEC("perf_event")
int on_cache_miss(struct bpf_perf_event_data *ctx)
{
    struct sample_t *s;

    s = bpf_ringbuf_reserve(&rb, sizeof(*s), 0);
    if (!s)
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    s->pid = id >> 32;
    s->tid = id & 0xffffffff;
    s->ip  = PT_REGS_IP(&ctx->regs);   // Program Counter (instrucción que falló en cache)
    s->ts  = bpf_ktime_get_ns();

    bpf_ringbuf_submit(s, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

