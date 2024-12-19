
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned int u32;
typedef int pid_t;

char __license[] SEC("license") = "Dual MIT/GPL";


SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
    return 0;
}

