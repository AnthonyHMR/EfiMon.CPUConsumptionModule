// main.cpp (versión que guarda las muestras en samples.csv)

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <csignal>
#include <vector>
#include <cstring>
#include <fstream>   // Para escribir CSV
#include <iomanip>   // Para std::hex y std::dec
#include <chrono>
#include <iostream>

#include "../include/prog.skel.h"

static volatile bool exiting = false;

// Estructura de la muestra recibida
struct sample_t {
    uint32_t pid;
    uint32_t tid;
    uint64_t ip;
    uint64_t ts;
};

// Vector global para almacenar las muestras
static std::vector<sample_t> samples;

// Manejador de señal (Ctrl+C)
static void sig_handler(int signo) {
    exiting = true;
}

// Envoltorio para perf_event_open
static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                           int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        return 1;
    }
    int target_pid = atoi(argv[1]);
    uint64_t sample_period = strtoull(argv[2], nullptr, 10);
    int duration = atoi(argv[3]);

    signal(SIGINT, sig_handler);

    // 1) Cargar eBPF
    prog_bpf *skel = prog_bpf__open_and_load();
    if (!skel) {
        return 1;
    }

    // 2) Configurar perf_event
    struct perf_event_attr attr{};
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.size = sizeof(attr);
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    attr.sample_period = sample_period;
    attr.precise_ip = 2;
    attr.disabled = 0;

    // 3) Abrir perf_event para el proceso (en todos los CPUs)
    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    std::vector<int> pfd(ncpus);

    int prog_fd = bpf_program__fd(skel->progs.on_sample);

    for (int cpu = 0; cpu < ncpus; cpu++) {
        pfd[cpu] = perf_event_open(&attr, target_pid, cpu, -1, 0);
        if (pfd[cpu] < 0)
            continue;

        if (ioctl(pfd[cpu], PERF_EVENT_IOC_SET_BPF, prog_fd) < 0)
            return 1;

        if (ioctl(pfd[cpu], PERF_EVENT_IOC_ENABLE, 0) < 0)
            return 1;
    }

    // 4) Configurar ring buffer (guardar muestras)
    auto handle_event = [](void *ctx, void *data, size_t size) {
        if (size == sizeof(sample_t)) {
            sample_t s;
            memcpy(&s, data, sizeof(sample_t));
            samples.push_back(s);
        }
        return 0;
    };

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                                              handle_event, nullptr, nullptr);
    if (!rb) {
        return 1;
    }

    // 5) Loop de captura
    auto start = std::chrono::steady_clock::now();
    while (!exiting) {
        ring_buffer__poll(rb, 100);
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
        if (elapsed >= duration)
            break;
    }

    // 6) Cleanup
    ring_buffer__free(rb);
    prog_bpf__destroy(skel);
    for (int fd : pfd)
        if (fd >= 0)
            close(fd);

    // 7) Guardar resultados en CSV
    //std::ofstream csv("samples.csv");
    //if (csv.is_open()) {
    //    csv << "pid,tid,ip,ts\n";
    //    for (const auto &s : samples) {
    //        csv << s.pid << ","
    //            << s.tid << ","
    //            << "0x" << std::hex << s.ip << std::dec << ","
    //            << s.ts << "\n";
    //    }
    //    csv.close();
    //}

    return 0;
}

