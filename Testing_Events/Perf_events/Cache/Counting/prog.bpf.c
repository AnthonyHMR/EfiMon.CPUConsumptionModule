// prog.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2); // 0 -> hits, 1 -> misses
    __type(key, u32);
    __type(value, u64);
} counters SEC(".maps");

/* PERF handler para hits */
SEC("perf_event")
int on_hit(struct bpf_perf_event_data *ctx)
{
    u32 key = 0;
    u64 *val = bpf_map_lookup_elem(&counters, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
    return 0;
}

/* PERF handler para misses */
SEC("perf_event")
int on_miss(struct bpf_perf_event_data *ctx)
{
    u32 key = 1;
    u64 *val = bpf_map_lookup_elem(&counters, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

