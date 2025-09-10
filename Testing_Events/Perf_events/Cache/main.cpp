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

// Estructura de muestra
struct sample_t {
    uint32_t pid;
    uint32_t tid;
    uint64_t count;
    uint64_t ts;
};

static volatile bool exiting = false;

static void sig_handler(int signo) {
    exiting = true;
}

// syscall perf_event_open
static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                           int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);

    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <PID> <cache> <hits|misses>\n";
        std::cerr << "cache = l1d | l1i | llc\n";
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    std::string cache = argv[2];
    std::string type = argv[3];

    // -------------------
    // Selección de evento
    // -------------------
    uint32_t result_flag;
    if (type == "hits") {
        result_flag = PERF_COUNT_HW_CACHE_RESULT_ACCESS;
    } else if (type == "misses") {
        result_flag = PERF_COUNT_HW_CACHE_RESULT_MISS;
    } else {
        std::cerr << "Invalid type, must be 'hits' or 'misses'\n";
        return 1;
    }

    uint32_t cache_flag;
    uint32_t op_flag = PERF_COUNT_HW_CACHE_OP_READ; // default: lecturas

    if (cache == "l1d") {
        cache_flag = PERF_COUNT_HW_CACHE_L1D;
    } else if (cache == "l1i") {
        cache_flag = PERF_COUNT_HW_CACHE_L1I;
        op_flag = PERF_COUNT_HW_CACHE_OP_READ; // fetch de instrucciones
    } else if (cache == "llc") {
        cache_flag = PERF_COUNT_HW_CACHE_LL;
    } else {
        std::cerr << "Invalid cache, must be l1d, l1i or llc\n";
        return 1;
    }

    // -------------------
    // Config perf_event
    // -------------------
    struct perf_event_attr attr{};
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HW_CACHE;
    attr.size = sizeof(attr);
    attr.config = cache_flag | (op_flag << 8) | (result_flag << 16);
    attr.disabled = 0;
    attr.inherit = 1;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 0;

    int fd = perf_event_open(&attr, target_pid, -1, -1, 0);
    if (fd < 0) {
        perror("perf_event_open");
        return 1;
    }

    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) < 0) {
        perror("ioctl(PERF_EVENT_IOC_RESET)");
        close(fd);
        return 1;
    }
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        perror("ioctl(PERF_EVENT_IOC_ENABLE)");
        close(fd);
        return 1;
    }

    // -------------------
    // Loop de muestreo
    // -------------------
    std::cout << "Monitoring PID " << target_pid
              << " cache=" << cache
              << " type=" << type << " ... Press Ctrl+C to stop\n";

    while (!exiting) {
        uint64_t count = 0;
        ssize_t res = read(fd, &count, sizeof(count));
        if (res != sizeof(count)) {
            perror("read");
            break;
        }

        uint64_t ts = static_cast<uint64_t>(time(nullptr)) * 1000000000ULL;

        std::cout << "PID " << target_pid
                  << " COUNT=" << count
                  << " TS=" << ts << "\n";

        sleep(1); // tomar muestra cada segundo
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    close(fd);
    return 0;
}

