// main.cpp
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <iostream>
#include <csignal>
#include <vector>
#include <cstring>

#include "prog.skel.h"   // generado con bpftool

static volatile bool exiting = false;

static void sig_handler(int signo) {
    exiting = true;
}

struct sample_t {
    uint32_t pid;
    uint32_t tid;
    uint64_t ip;
    uint64_t ts;
};

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                           int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <PID>" << std::endl;
        return 1;
    }
    int target_pid = atoi(argv[1]);

    signal(SIGINT, sig_handler);

    // 1) Cargar eBPF
    prog_bpf *skel = prog_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to open/load BPF skeleton\n";
        return 1;
    }

    // 2) Configurar perf_event
    struct perf_event_attr attr{};
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;  // ciclos → da IP
    attr.size = sizeof(attr);
    attr.freq = 1;
    attr.sample_freq = 1000; // 1k muestras por segundo
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    attr.precise_ip = 2; // lo más preciso posible
    attr.disabled = 0;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 1;
    attr.inherit = 1;

    // 3) Abrir perf_event para el proceso (en todos los CPUs)
    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    std::vector<int> pfd(ncpus);

    int prog_fd = bpf_program__fd(skel->progs.on_sample);

    for (int cpu = 0; cpu < ncpus; cpu++) {
        pfd[cpu] = perf_event_open(&attr, target_pid, cpu, -1, 0);
        if (pfd[cpu] < 0) {
            perror("perf_event_open");
            continue;
        }
        if (ioctl(pfd[cpu], PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
            perror("PERF_EVENT_IOC_SET_BPF");
            return 1;
        }
        if (ioctl(pfd[cpu], PERF_EVENT_IOC_ENABLE, 0) < 0) {
            perror("PERF_EVENT_IOC_ENABLE");
            return 1;
        }
    }

    // 4) Configurar ring buffer
    auto handle_event = [](void *ctx, void *data, size_t size) {
        auto *s = (sample_t *)data;
        std::cout << "PID " << s->pid
                  << " TID " << s->tid
                  << " IP 0x" << std::hex << s->ip
                  << " TS " << std::dec << s->ts << "\n";
        return 0;
    };

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                                              handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to setup ring buffer\n";
        return 1;
    }

    // 5) Loop
    while (!exiting) {
        ring_buffer__poll(rb, 100 /*ms*/);
    }

    // 6) Cleanup
    ring_buffer__free(rb);
    prog_bpf__destroy(skel);
    for (int fd : pfd) if (fd >= 0) close(fd);
    return 0;
}

