// sys_enter_openat.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    long dirfd = ctx->args[0];
    unsigned long filename_ptr = ctx->args[1];
    unsigned long flags = ctx->args[2];

    char filename[128] = {};
    if (filename_ptr) {
        bpf_probe_read_user_str(filename, sizeof(filename), (const void *)filename_ptr);
    }

    bpf_printk("sys_enter_openat: pid=%d dirfd=%ld file=%s flags=%lu\n",
               pid, dirfd, filename, flags);
    return 0;
}

