//go:build ignore

#include "common.h"
#include <bpf/bpf_tracing.h>
#include <stdbool.h>


char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct data_t *unused __attribute__((unused));


struct data_t {
    __u32 pid;
    __u8 comm[80];//TASK_COMM_LEN
    __u64 args[5];
    __u64 ret;
    bool entry;
    __u64 ktime_ns;
};

SEC("uprobe")
int uprobe_entry(struct pt_regs *ctx) {
    struct data_t data = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    // Fill in the arguments
    data.args[0] = PT_REGS_PARM1(ctx);
    data.args[1] = PT_REGS_PARM2(ctx);
    data.args[2] = PT_REGS_PARM3(ctx);
    data.args[3] = PT_REGS_PARM4(ctx);
    data.args[4] = PT_REGS_PARM5(ctx);
    data.entry = true;
    data.ktime_ns = bpf_ktime_get_ns();

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("uretprobe")
int uprobe_return(struct pt_regs *ctx) {
    struct data_t data = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    u64 ret = PT_REGS_RC(ctx);
    data.ret = ret;
    data.entry = false;
    data.ktime_ns = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}