#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <chrono>
#include "prog.skel.h"

static volatile bool exiting = false;
static void sig_handler(int signo) { exiting = true; }

// Contador global de muestras
static size_t sample_count = 0;

int handle_event(void* ctx, void* data, size_t size) {
    sample_count++; // contar cada muestra
    return 0;
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
    if (argc < 3) return 1; // <PID> <hits|misses>

    pid_t target_pid = atoi(argv[1]);
    std::string type = argv[2];

    uint32_t result_flag;
    if (type == "hits") result_flag = PERF_COUNT_HW_CACHE_RESULT_ACCESS;
    else if (type == "misses") result_flag = PERF_COUNT_HW_CACHE_RESULT_MISS;
    else return 1;

    // Leer frecuencia y duración opcionales
    int freq = 1000;    // Hz por defecto
    int duration = 10;  // segundos por defecto
    for(int i=3;i<argc;i++){
        if(strncmp(argv[i],"--freq=",7)==0) freq = atoi(argv[i]+7);
        if(strncmp(argv[i],"--duration=",11)==0) duration = atoi(argv[i]+11);
    }

    signal(SIGINT, sig_handler);

    struct prog_bpf *skel = prog_bpf__open_and_load();
    if(!skel) return 1;

    struct perf_event_attr attr{};
    memset(&attr,0,sizeof(attr));
    attr.type = PERF_TYPE_HW_CACHE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_HW_CACHE_L1D |
                  (PERF_COUNT_HW_CACHE_OP_READ<<8) |
                  (result_flag<<16);
    attr.sample_period = 1000000/freq; // period aproximado
    attr.disabled = 0;

    int prog_fd = bpf_program__fd(skel->progs.on_cache_miss);
    int fd = perf_event_open(&attr,target_pid,-1,-1,0);
    if(fd<0) return 1;
    if(ioctl(fd,PERF_EVENT_IOC_SET_BPF,prog_fd)<0) return 1;
    if(ioctl(fd,PERF_EVENT_IOC_ENABLE,0)<0) return 1;

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                                              handle_event,nullptr,nullptr);
    if(!rb) return 1;

    auto start = std::chrono::steady_clock::now();
    while(!exiting){
        ring_buffer__poll(rb,100);
        auto now = std::chrono::steady_clock::now();
        if(std::chrono::duration_cast<std::chrono::seconds>(now-start).count() >= duration)
            break;
    }

    // Cleanup
    ring_buffer__free(rb);
    prog_bpf__destroy(skel);
    close(fd);

    // Al finalizar, sample_count tiene el total de muestras
    return 0;
}

