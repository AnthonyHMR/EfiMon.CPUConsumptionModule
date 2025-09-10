// main.cpp
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <thread>

#include "prog.skel.h"

static volatile bool exiting = false;
static void handle_sig(int) { exiting = true; }

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                           int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <PID> [sample_period]\n";
        std::cerr << "  sample_period: number of events between samples (default 1000)\n";
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    uint64_t sample_period = 1000;
    if (argc >= 3) sample_period = std::stoull(argv[2]);

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    /* load BPF skeleton */
    struct prog_bpf *skel = prog_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to open/load BPF skeleton\n";
        return 1;
    }

    /* map fd for counters (per-cpu array) */
    int map_fd = bpf_map__fd(skel->maps.counters);
    if (map_fd < 0) {
        std::cerr << "Failed to get map fd\n";
        prog_bpf__destroy(skel);
        return 1;
    }

    /* Prepare two perf_event_attr: one para hits (ACCESS) y otro para misses (MISS) */
    struct perf_event_attr attr{};
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HW_CACHE;
    attr.size = sizeof(attr);
    /* We'll set config per-event below */

    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus <= 0) ncpus = 1;

    /* open hits event (L1D READ ACCESS) */
    struct perf_event_attr attr_hits = attr;
    attr_hits.config = PERF_COUNT_HW_CACHE_L1D |
                       (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                       (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16);
    attr_hits.sample_period = sample_period;
    attr_hits.disabled = 0;
    attr_hits.exclude_hv = 1;
    attr_hits.exclude_kernel = 1; // opcional: medir solo user-space; cambia si quieres kernel también

    /* open misses event (L1D READ MISS) */
    struct perf_event_attr attr_miss = attr_hits;
    attr_miss.config = PERF_COUNT_HW_CACHE_L1D |
                       (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                       (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);

    /* Abrimos un evento por proceso (PID) en todas las CPUs (cpu = -1) */
    int fd_hits = perf_event_open(&attr_hits, target_pid, -1, -1, 0);
    if (fd_hits < 0) {
        perror("perf_event_open (hits)");
        prog_bpf__destroy(skel);
        return 1;
    }

    int fd_miss = perf_event_open(&attr_miss, target_pid, -1, -1, 0);
    if (fd_miss < 0) {
        perror("perf_event_open (miss)");
        close(fd_hits);
        prog_bpf__destroy(skel);
        return 1;
    }

    /* attach corresponding BPF programs (on_hit, on_miss) */
    int prog_fd_hit = bpf_program__fd(skel->progs.on_hit);
    int prog_fd_miss = bpf_program__fd(skel->progs.on_miss);

    if (ioctl(fd_hits, PERF_EVENT_IOC_SET_BPF, prog_fd_hit) < 0) {
        perror("PERF_EVENT_IOC_SET_BPF (hit)");
        close(fd_hits); close(fd_miss);
        prog_bpf__destroy(skel);
        return 1;
    }
    if (ioctl(fd_miss, PERF_EVENT_IOC_SET_BPF, prog_fd_miss) < 0) {
        perror("PERF_EVENT_IOC_SET_BPF (miss)");
        close(fd_hits); close(fd_miss);
        prog_bpf__destroy(skel);
        return 1;
    }

    if (ioctl(fd_hits, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        perror("PERF_EVENT_IOC_ENABLE (hit)");
    }
    if (ioctl(fd_miss, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        perror("PERF_EVENT_IOC_ENABLE (miss)");
    }

    /* Buffers to read per-cpu values: per-cpu array -> ncpus entries */
    std::vector<uint64_t> percpu_vals(ncpus);
    std::vector<uint64_t> zeros(ncpus, 0);

    std::cout << "Monitoring PID " << target_pid << " (sample_period=" << sample_period << "). Press Ctrl-C to stop.\n";

    while (!exiting) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Read hits (key=0)
        uint32_t key = 0;
        memset(percpu_vals.data(), 0, sizeof(uint64_t) * ncpus);
        if (bpf_map_lookup_elem(map_fd, &key, percpu_vals.data()) != 0) {
            perror("bpf_map_lookup_elem (hits)");
        }
        uint64_t sum_hits = 0;
        for (int i = 0; i < ncpus; ++i) sum_hits += percpu_vals[i];

        // Read misses (key=1)
        key = 1;
        memset(percpu_vals.data(), 0, sizeof(uint64_t) * ncpus);
        if (bpf_map_lookup_elem(map_fd, &key, percpu_vals.data()) != 0) {
            perror("bpf_map_lookup_elem (misses)");
        }
        uint64_t sum_misses = 0;
        for (int i = 0; i < ncpus; ++i) sum_misses += percpu_vals[i];

        // Mostrar los totales (una vez por segundo)
        std::cout << "1s: hits=" << sum_hits << "  misses=" << sum_misses << "  (sample_period=" << sample_period << ")\n";

        // Reset counters a 0 (actualizamos con per-cpu zeros)
        key = 0;
        if (bpf_map_update_elem(map_fd, &key, zeros.data(), BPF_ANY) != 0) {
            perror("bpf_map_update_elem (reset hits)");
        }
        key = 1;
        if (bpf_map_update_elem(map_fd, &key, zeros.data(), BPF_ANY) != 0) {
            perror("bpf_map_update_elem (reset misses)");
        }
    }

    // cleanup
    close(fd_hits);
    close(fd_miss);
    prog_bpf__destroy(skel);
    return 0;
}

