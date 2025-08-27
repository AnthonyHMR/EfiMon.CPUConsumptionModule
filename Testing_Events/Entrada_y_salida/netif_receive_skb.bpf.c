// netif_receive_skb.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

// tracepoint netif_receive_skb
struct trace_event_raw_netif_receive_skb {
    char name[16];
    unsigned int len;
    unsigned int protocol;
};

SEC("tracepoint/net/netif_receive_skb")
int handle_netif_receive_skb(struct trace_event_raw_netif_receive_skb *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("netif_receive_skb: pid=%d dev=%s len=%u proto=0x%x\n",
               pid, ctx->name, ctx->len, ctx->protocol);
    return 0;
}

