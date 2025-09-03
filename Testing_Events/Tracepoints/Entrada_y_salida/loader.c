// loader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

static volatile int exiting = 0;

static void sig_handler(int sig) {
    exiting = 1;
}

static int bump_memlock_rlimit(void) {
    struct rlimit rlim_new = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    if (argc < 2) {
        fprintf(stderr, "Uso: %s <archivo.bpf.o>\n", argv[0]);
        return 1;
    }

    if (bump_memlock_rlimit()) {
        perror("setrlimit");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error abriendo %s\n", argv[1]);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error cargando programa BPF\n");
        return 1;
    }

    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Error adjuntando %s\n", bpf_program__name(prog));
            return 1;
        }
        printf("Adjuntado: %s\n", bpf_program__name(prog));
    }

    printf("Programa en ejecución. Ver salida con:\n");
    printf("  sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

    while (!exiting) sleep(1);
    return 0;
}

