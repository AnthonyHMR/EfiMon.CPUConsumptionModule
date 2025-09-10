// cache_count.cpp

#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
#include <csignal>
#include <cstdint>
#include <cstdlib>

static volatile bool exiting = false;
static void on_sig(int) { exiting = true; }

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                           int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PID>\n";
        return 1;
    }
    pid_t target = static_cast<pid_t>(atoi(argv[1]));
    signal(SIGINT, on_sig);

    // --- configurar evento: L1D READ ACCESS (hits) ---
    struct perf_event_attr attr_hits;
    memset(&attr_hits, 0, sizeof(attr_hits));
    attr_hits.type = PERF_TYPE_HW_CACHE;
    attr_hits.size = sizeof(attr_hits);
    attr_hits.config =
        PERF_COUNT_HW_CACHE_L1D |
        (PERF_COUNT_HW_CACHE_OP_READ << 8) |
        (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16);
    // modo counting (no sample)
    attr_hits.disabled = 0;
    attr_hits.exclude_kernel = 0; // incluye kernel si lo deseas
    attr_hits.exclude_hv = 1;

    // --- configurar evento: L1D READ MISS (misses) ---
    struct perf_event_attr attr_miss;
    memset(&attr_miss, 0, sizeof(attr_miss));
    attr_miss.type = PERF_TYPE_HW_CACHE;
    attr_miss.size = sizeof(attr_miss);
    attr_miss.config =
        PERF_COUNT_HW_CACHE_L1D |
        (PERF_COUNT_HW_CACHE_OP_READ << 8) |
        (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
    attr_miss.disabled = 0;
    attr_miss.exclude_kernel = 0;
    attr_miss.exclude_hv = 1;

    // Abrir ambos perf events ligados al PID en todos los CPUs (cpu = -1)
    int fd_hits = perf_event_open(&attr_hits, target, -1, -1, 0);
    if (fd_hits < 0) { perror("perf_event_open hits"); return 1; }
    int fd_miss = perf_event_open(&attr_miss, target, -1, -1, 0);
    if (fd_miss < 0) { perror("perf_event_open misses"); close(fd_hits); return 1; }

    // Asegurarnos que están habilitados
    if (ioctl(fd_hits, PERF_EVENT_IOC_ENABLE, 0) != 0) perror("ioctl enable hits");
    if (ioctl(fd_miss, PERF_EVENT_IOC_ENABLE, 0) != 0) perror("ioctl enable misses");

    uint64_t last_hits = 0, last_misses = 0;

    // loop cada segundo: leer contadores y mostrar delta
    while (!exiting) {
        sleep(1);

        uint64_t cur_hits = 0, cur_misses = 0;
        ssize_t r1 = read(fd_hits, &cur_hits, sizeof(cur_hits));
        ssize_t r2 = read(fd_miss, &cur_misses, sizeof(cur_misses));
        if (r1 != sizeof(cur_hits)) {
            // handle error (podría ser -1 con errno)
            if (r1 < 0) perror("read hits");
        }
        if (r2 != sizeof(cur_misses)) {
            if (r2 < 0) perror("read misses");
        }

        uint64_t delta_hits = (cur_hits >= last_hits) ? (cur_hits - last_hits) : cur_hits;
        uint64_t delta_miss = (cur_misses >= last_misses) ? (cur_misses - last_misses) : cur_misses;

        // Mostrar los resultados agregados por segundo
        std::cout << "PID " << target
                  << " | hits/s: " << delta_hits
                  << " | misses/s: " << delta_miss << std::endl;

        last_hits = cur_hits;
        last_misses = cur_misses;
    }

    close(fd_hits);
    close(fd_miss);
    return 0;
}

