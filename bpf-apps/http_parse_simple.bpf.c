#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helper_defs.h>
#include <bpf/bpf_helpers.h>

#define ETH_HLEN 14 /* Total octets in header.	 */

#define DATA_LEN 7

SEC("http_filter/simple")
int http_filter(struct __sk_buff *skb)
{
    bpf_skb_pull_data(skb, 0);

    __u16 h_proto;
    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto)) < 0)
    {
        goto DROP;
    }
    if (bpf_ntohs(h_proto) != ETH_P_IP)
    {
        goto DROP;
    }
    
    __u8 protocol;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &protocol, sizeof(protocol)) < 0)
    {
        goto DROP;
    }
    if (protocol != IPPROTO_TCP)
    {
        goto DROP;
    }

    struct tcphdr tcp_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &tcp_hdr, sizeof(tcp_hdr)) < 0)
    {
        goto DROP;
    }
    if (tcp_hdr.psh == 0)   // no payload
    {
        goto DROP;
    }

    // parse tcp payload
    __u16 offset = ETH_HLEN + sizeof(struct iphdr) + (tcp_hdr.doff << 2);
    if (offset == 0 || offset > skb->len)
    {
        goto DROP;
    }

    unsigned long p[DATA_LEN];
    int i;
    for (i = 0; i < DATA_LEN; i++)
    {
        char b;
        bpf_skb_load_bytes(skb, offset + i, &b, 1);
        if (b == '\0')
        {
            break;
        }
        p[i] = b;
    }
    
    char fmt[] = "payload:\n%s";
    bpf_trace_printk(fmt, sizeof(fmt), p);

    // find a match with an HTTP message
    // HTTP
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P'))
    {
        goto KEEP;
    }
    // GET
    if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T'))
    {
        goto KEEP;
    }
    // POST
    if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T'))
    {
        goto KEEP;
    }
    // PUT
    if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T'))
    {
        goto KEEP;
    }
    // DELETE
    if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E'))
    {
        goto KEEP;
    }
    // HEAD
    if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D'))
    {
        goto KEEP;
    }

    // no HTTP match
    goto DROP;

    // keep the packet and send it to userspace returing -1
    KEEP:
    return -1;

    // drop the packet returing 0
    DROP:
    return 0;
    
}