/*
 * nkbinder_network.bpf.c
 * Network packet notification for nkbinder - eBPF non-CO-RE implementation
 *
 * This uses BPF_PROG_TYPE_SOCKET_FILTER with stable BPF helper functions:
 *   - bpf_get_socket_uid() - get UID from socket
 *   - bpf_skb_load_bytes() - load packet bytes
 *   - bpf_skb_protocol() - get L3 protocol
 *
 * No CO-RE required - these helpers abstract kernel struct layouts internally.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "nkbinder.h"

/* Ring buffer for network events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_rb SEC(".maps");

/*
 * Socket filter BPF program
 *
 * Attaches to raw sockets and receives all packets.
 * Uses only stable BPF helper functions - NO CO-RE required.
 */
SEC("socket_filter")
int nkbinder_sock_filter(struct __sk_buff *skb)
{
    struct nkbinder_event *event;
    __u32 uid;
    __u8 proto;
    __u8 ip_version;
    __u32 hdr_len;
    __u32 payload_len;
    int err;

    /* Get UID from the socket that received this packet */
    uid = bpf_get_socket_uid(skb);
    if (uid < MIN_USERAPP_UID)
        return 0;

    /* Get network protocol */
    proto = bpf_skb_protocol(skb);
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return 0;

    /*
     * Load first 4 bytes to determine IP version and parse header.
     * Using bpf_skb_load_bytes which is a stable helper function.
     */
    __u8 ip_hdr[4];
    err = bpf_skb_load_bytes(skb, 0, ip_hdr, sizeof(ip_hdr));
    if (err < 0)
        return 0;

    /* Parse IP version from first nibble */
    ip_version = (ip_hdr[0] >> 4) & 0xF;

    if (ip_version == 4) {
        /* IPv4: standard header is 20 bytes (no options typically) */
        hdr_len = 20;

        if (proto == IPPROTO_TCP)
            payload_len = ip_hdr[2] * 256 + ip_hdr[3] - hdr_len - 20;
        else /* UDP */
            payload_len = ip_hdr[2] * 256 + ip_hdr[3] - hdr_len - 8;

    } else if (ip_version == 6) {
        /* IPv6: fixed header is 40 bytes */
        hdr_len = 40;

        /* IPv6 payload length is at bytes 4-5 */
        __u8 ipv6_payload[2];
        err = bpf_skb_load_bytes(skb, 4, ipv6_payload, sizeof(ipv6_payload));
        if (err < 0)
            return 0;

        if (proto == IPPROTO_TCP)
            payload_len = ipv6_payload[0] * 256 + ipv6_payload[1] - 20;
        else /* UDP */
            payload_len = ipv6_payload[0] * 256 + ipv6_payload[1] - 8;

    } else {
        return 0;
    }

    /* For TCP, negative payload means control-only packet (pure ACK, etc.) */
    if (payload_len < 0)
        payload_len = 0;

#ifdef DEBUG
    bpf_printk("nkbinder: uid=%u proto=%s payload=%d\n",
               uid, proto == IPPROTO_TCP ? "TCP" : "UDP", payload_len);
#endif

    /* Reserve event from ring buffer */
    event = bpf_ringbuf_reserve(&network_rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = TYPE_NETWORK;
    event->network.uid = (int)uid;
    event->network.family = (ip_version == 6) ? NF_FAMILY_IPV6 : NF_FAMILY_IPV4;
    event->network.data_len = (int)payload_len;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
