// sys_enter_execve.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    char filename[128] = {};
    unsigned long filename_ptr = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // obtener puntero a filename
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &ctx->args[0]);
    if (filename_ptr) {
        bpf_probe_read_user_str(filename, sizeof(filename), (const void *)filename_ptr);
    }

    bpf_printk("sys_enter_execve: pid=%d filename=%s\n", pid, filename);
    return 0;
}

