//go:build ignore
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// 유저 스페이스로 보낼 데이터 구조
struct event {
    u32 pid;
    u64 start_time_ns;
    u64 duration_ns;
    char comm[16]; // 프로세스 이름
};

// 시작 시간을 임시 저장할 Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240);
} start_times SEC(".maps");

// 데이터를 유저 스페이스로 보낼 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_times, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_execve")
int kretprobe_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start_ts, end_ts = bpf_ktime_get_ns();

    start_ts = bpf_map_lookup_elem(&start_times, &pid);
    if (!start_ts) return 0;

    // Ring Buffer에서 메모리 할당
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->start_time_ns = *start_ts;
    e->duration_ns = end_ts - *start_ts;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 유저 스페이스로 전송
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&start_times, &pid);
    return 0;
}
