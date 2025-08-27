// loader.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    struct bpf_link *links[32];
    int link_count = 0;
    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <tracepoints.bpf.o>\n", argv[0]);
        return 1;
    }

    if (bump_memlock_rlimit()) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error abriendo objeto BPF: %s\n", argv[1]);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error cargando objeto BPF: %d\n", err);
        goto cleanup;
    }

    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Error adjuntando programa: %s\n", bpf_program__name(prog));
            link = NULL;
            goto cleanup;
        }
        if (link_count < (int)(sizeof(links)/sizeof(links[0]))) {
            links[link_count++] = link;
            link = NULL; // ownership moved
        } else {
            fprintf(stderr, "Demasiados programas para almacenar links\n");
            goto cleanup;
        }
        printf("Adjuntado: %s\n", bpf_program__name(prog));
    }

    printf("Programas eBPF cargados y adjuntados. Mirar /sys/kernel/debug/tracing/trace_pipe para salida.\n");

    while (!exiting) {
        sleep(1);
    }

    printf("Saliendo, limpiando enlaces...\n");

cleanup:
    for (int i = 0; i < link_count; ++i) {
        if (links[i])
            bpf_link__destroy(links[i]);
    }
    if (obj)
        bpf_object__close(obj);

    return 0;
}

