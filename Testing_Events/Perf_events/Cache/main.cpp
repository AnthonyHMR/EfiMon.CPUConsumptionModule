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

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <PID> <event> [hits|misses]\n";
        std::cerr << "event = l1d | l1i | llc | branch_misses\n";
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    std::string event = argv[2];
    std::string type = argc >= 4 ? argv[3] : "";

    struct perf_event_attr attr{};
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);

    // -------------------
    // Selección de evento
    // -------------------
    if (event == "branch_misses") {
        attr.type = PERF_TYPE_HARDWARE;
        attr.config = PERF_COUNT_HW_BRANCH_MISSES;
    } else {
        uint32_t result_flag;
        if (type == "hits") {
            result_flag = PERF_COUNT_HW_CACHE_RESULT_ACCESS;
        } else if (type == "misses") {
            result_flag = PERF_COUNT_HW_CACHE_RESULT_MISS;
        } else {
            std::cerr << "For cache events, you must specify 'hits' or 'misses'\n";
            return 1;
        }

        uint32_t cache_flag;
        uint32_t op_flag = PERF_COUNT_HW_CACHE_OP_READ; // default: lecturas

        if (event == "l1d") {
            cache_flag = PERF_COUNT_HW_CACHE_L1D;
        } else if (event == "l1i") {
            cache_flag = PERF_COUNT_HW_CACHE_L1I;
            op_flag = PERF_COUNT_HW_CACHE_OP_READ; // fetch de instrucciones
        } else if (event == "llc") {
            cache_flag = PERF_COUNT_HW_CACHE_LL;
        } else {
            std::cerr << "Invalid cache, must be l1d, l1i, llc or branch_misses\n";
            return 1;
        }

        attr.type = PERF_TYPE_HW_CACHE;
        attr.config = cache_flag | (op_flag << 8) | (result_flag << 16);
    }

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
              << " event=" << event
              << (type.empty() ? "" : " type=" + type)
              << " ... Press Ctrl+C to stop\n";

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

