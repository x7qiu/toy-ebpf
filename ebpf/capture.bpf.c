#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- Fix for Missing Constants
#define ETH_P_IP  0x0800 // IPv4 protocol number (Host Byte Order)
#define IPPROTO_TCP 6    // TCP protocol number
#define IPPROTO_UDP 17   // UDP protocol number

struct ethhdr_t {
    unsigned char  h_dest[6];
    unsigned char  h_source[6];
    __be16 h_proto;
} __attribute__((packed));

struct iphdr_t {
    __u8 ihl:4;
    __u8 version:4;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct tcphdr_t {
    __be16 source;
    __be16 dest;
} __attribute__((packed)); // Only need source/dest for flow info

struct udphdr_t {
    __be16 source;
    __be16 dest;
} __attribute__((packed)); // Only need source/dest for flow info


// C struct definition MUST match the Go struct layout exactly.
// __attribute__((packed)) prevents compiler padding and forces 1-byte alignment,
// which matches the 'align:"1"' tag in the Go struct.
struct packet_info {
    unsigned char  DestMac[6];
    unsigned char  SrcMac[6];
    __u32 Saddr;
    __u32 Daddr;
    __u16 Sport;
    __u16 Dport;
    __u8 Protocol;
    __u64 PktCount;
    __u32 ByteCount;
} __attribute__((packed));

// A ring buffer map for sending data to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} packets SEC(".maps");


SEC("xdp")
int NetMonitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr_t *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS; // Pass non-IPv4 packets
    }

    struct iphdr_t *ip = (void *)eth + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Check if the packet is IPv4
    if (ip->version != 4) {
        return XDP_PASS;
    }
    
    // Calculate IP header length
    __u16 ip_hdr_len = ip->ihl * 4;
    if ((void *)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    // Reserve space in the ring buffer for flow data
    struct packet_info *info = bpf_ringbuf_reserve(&packets, sizeof(struct packet_info), 0);
    if (!info) {
        return XDP_PASS;
    }
    
    // Copy MACs, IPs, Protocol, and Byte Count
    for (int i = 0; i < 6; i++) {
        info->DestMac[i] = eth->h_dest[i];
        info->SrcMac[i] = eth->h_source[i];
    }
    info->Saddr = bpf_ntohl(ip->saddr);
    info->Daddr = bpf_ntohl(ip->daddr);
    info->Protocol = ip->protocol;
    info->ByteCount = bpf_ntohs(ip->tot_len) + 14; // IP length + Ethernet header
    info->PktCount = 1;

    // Default to 0 ports
    info->Sport = 0;
    info->Dport = 0;

    // Check for TCP or UDP to extract ports
    void *transport_hdr = (void *)ip + ip_hdr_len;
    if (transport_hdr + sizeof(struct udphdr_t) <= data_end) {
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr_t *tcp = transport_hdr;
            info->Sport = bpf_ntohs(tcp->source);
            info->Dport = bpf_ntohs(tcp->dest);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr_t *udp = transport_hdr;
            info->Sport = bpf_ntohs(udp->source);
            info->Dport = bpf_ntohs(udp->dest);
        }
    }
    
    bpf_ringbuf_submit(info, 0);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
