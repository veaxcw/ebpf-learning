#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>  // For ETH_P_IP
#include <linux/in.h>        // For IPPROTO_TCP
#include <linux/ip.h>        // For struct iphdr
#include <linux/tcp.h>       // For struct tcphdr
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0

char __license[] SEC("license") = "Dual MIT/GPL";

struct data_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 total;
    __u32 ttl;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");


SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct tcphdr *l4;
    struct data_t pkt_data = {};

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
       return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    if (l3->protocol != IPPROTO_TCP)
            return TC_ACT_OK;

    l4 = (struct tcphdr *)(l3 + 1);
    if ((void *)(l4 + 1) > data_end)
        return TC_ACT_OK;
    // 将网络字节顺序改成主机字节顺序bpf_ntohs，网络字节顺序是大端
    pkt_data.saddr = l3->saddr;
    pkt_data.daddr = l3->daddr;
    pkt_data.sport = bpf_ntohs(l4->source);
    pkt_data.dport = bpf_ntohs(l4->dest);
    pkt_data.total = l3->tot_len;
    pkt_data.ttl = l3->ttl;

    // 通过 perf event map 将数据传递到用户态
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pkt_data, sizeof(pkt_data));

    return TC_ACT_OK;
}
