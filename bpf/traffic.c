// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

struct key_t {
    u32 src_ip;
    u32 dst_ip;
    u32 direction; // 0: Ingress, 1: Egress
};

struct value_t {
    u64 packets;
    u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_t);
    __type(value, struct value_t);
} traffic_stats SEC(".maps");

static __always_inline int handle_pkt(struct __sk_buff *skb, u32 direction) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct key_t key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.direction = direction;

    struct value_t *val = bpf_map_lookup_elem(&traffic_stats, &key);
    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, skb->len);
    } else {
        struct value_t new_val = {1, skb->len};
        bpf_map_update_elem(&traffic_stats, &key, &new_val, BPF_ANY);
    }

    return TC_ACT_OK;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    return handle_pkt(skb, 0);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    return handle_pkt(skb, 1);
}

char __license[] SEC("license") = "GPL";
