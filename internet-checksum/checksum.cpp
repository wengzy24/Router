#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

bool validateAndFillChecksum(uint8_t *packet, size_t len) {
  // TODO
  bool ret = true;
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;

  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;
  if (nxt_header == IPPROTO_UDP) {
    // UDP
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    // length: udp->uh_ulen
    // checksum: udp->uh_sum

    uint32_t sum = 0;
    for(uint16_t *p = (uint16_t *) packet, *h = p + udp->uh_ulen; p < h; ++p){
      sum += *p;
    }
    while(sum > 0xffff){sum = sum % 16 + (sum >> 16);}
    ret = (udp->uh_sum != 0) & (sum == udp->uh_sum);

    sum = 0;
    udp->uh_sum = 0;
    for(uint16_t *p = (uint16_t *) packet, *h = p + udp->uh_ulen; p < h; ++p){
      sum += *p;
    }
    while(sum > 0xffff){sum = sum % 16 + (sum >> 16);}
    sum = __builtin_bswap16(uint16_t(sum));
    if(sum == 0x0000){sum = 0xffff;}
    udp->uh_sum = sum;

  } else if (nxt_header == IPPROTO_ICMPV6) {
    // ICMPv6
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
    // length: len-sizeof(struct ip6_hdr)
    // checksum: icmp->icmp6_cksum
    printf("%u\n\n", len-sizeof(struct ip6_hdr));
    uint32_t sum = 0;
    for(uint16_t *p = (uint16_t *) packet, *h = p + len-sizeof(struct ip6_hdr) / 2 + 20; p < h; ++p){
      sum += *p;
      printf("%u\n", *p);
    }
    while(sum > 0xffff){sum = sum % 16 + (sum / 16);}
    printf("%u\n", sum);
    ret = (sum == icmp->icmp6_cksum);

    sum = 0;
    icmp->icmp6_cksum = 0;
    for(uint16_t *p = (uint16_t *) packet, *h = p + len-sizeof(struct ip6_hdr) / 2 + 20; p < h; ++p){
      sum += *p;
    }
    while(sum > 0xffff){sum = sum % 16 + (sum / 16);}
    sum = __builtin_bswap16(uint16_t(sum));
    printf("%u\n", sum);
    icmp->icmp6_cksum = sum;
  } else {
    assert(false);
  }
  return ret;
}
