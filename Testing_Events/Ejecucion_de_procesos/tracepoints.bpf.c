// tracepoints.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

// License
char LICENSE[] SEC("license") = "GPL";

/*
 * Minimal structs used to access common fields from tracepoints.
 * Estas definiciones son las que usan la mayoría de ejemplos (bcc/bpftrace).
 * Pueden requerir ajustes si tu kernel tiene diferente layout
 * (en kernels con BTF no hace falta redeclarar).
 */

/* sys_enter: args[0] es filename (char *), args[1].. son ptrs a argv/envp */
struct trace_event_raw_sys_enter {
    unsigned long long pad;
    long id;
    unsigned long args[6];
};

/* sys_exit: ret value en 'ret' o similar */
struct trace_event_raw_sys_exit {
    unsigned long long pad;
    long id;
    long ret;
};

/* sched_switch: tiene prev_comm, prev_pid, next_comm, next_pid, ... */
struct trace_event_raw_sched_switch {
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    unsigned long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

/* sched_wakeup: common fields: comm, pid, prio, success? */
struct trace_event_raw_sched_wakeup {
    char comm[16];
    int pid;
    int prio;
    int success;
};

/* sched_process_exit */
struct trace_event_raw_sched_process_exit {
    char comm[16];
    int pid;
    /* other fields omitted */
};

/* sched_process_fork: parent_comm, parent_pid, child_comm, child_pid */
struct trace_event_raw_sched_process_fork {
    char parent_comm[16];
    int parent_pid;
    char child_comm[16];
    int child_pid;
};

/* Helper buffer size for strings */
#define STR_BUF_SZ 128

/* sys_enter_execve */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    char filename[STR_BUF_SZ] = {};
    unsigned long filename_ptr = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* args[0] should be pointer to filename */
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &ctx->args[0]);
    if (filename_ptr) {
        /* leer la cadena del espacio de usuario (según privilegios) */
        bpf_probe_read_user_str(&filename, sizeof(filename), (const void *)filename_ptr);
    }

    bpf_printk("sys_enter_execve: pid=%d file=%s\n", pid, filename);
    return 0;
}

/* sys_exit_execve (muestra retorno) */
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    long ret = ctx->ret;

    bpf_printk("sys_exit_execve: pid=%d ret=%ld\n", pid, ret);
    return 0;
}

/* sched_switch */
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    /* prev_comm y next_comm son arrays de 16 chars */
    bpf_printk("sched_switch: %s(%d) -> %s(%d)\n",
               ctx->prev_comm, ctx->prev_pid,
               ctx->next_comm, ctx->next_pid);
    return 0;
}

/* sched_wakeup */
SEC("tracepoint/sched/sched_wakeup")
int trace_sched_wakeup(struct trace_event_raw_sched_wakeup *ctx)
{
    bpf_printk("sched_wakeup: comm=%s pid=%d prio=%d success=%d\n",
               ctx->comm, ctx->pid, ctx->prio, ctx->success);
    return 0;
}

/* sched_process_exit */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    bpf_printk("sched_process_exit: comm=%s pid=%d\n",
               ctx->comm, ctx->pid);
    return 0;
}

/* sched_process_fork */
SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    bpf_printk("sched_process_fork: parent=%s(%d) -> child=%s(%d)\n",
               ctx->parent_comm, ctx->parent_pid,
               ctx->child_comm, ctx->child_pid);
    return 0;
}

