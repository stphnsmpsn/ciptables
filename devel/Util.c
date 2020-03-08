#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <linux/netfilter/xt_DSCP.h>
#include "Ciptables.h"
#include "Util.h"

#define ALL 0
#define TCP 1
#define UDP 2
#define UDPLITE 3
#define ICMP 4
#define ICMPV6 5
#define ESP 6
#define AH 7
#define SCTP 8
#define MH 9
#define UNKNOWN 10

static const char *const printableProto[] = {
    "all",
    "tcp",
    "udp",
    "udplite",
    "icmp",
    "icmpv6",
    "esp",
    "ah",
    "sctp",
    "mh",
    "unknown"};

void GetPrintableIp(uint32_t addr, char *result, size_t maxLen)
{
  if (addr == 0)
  {
    snprintf(result, maxLen, "anywhere");
  }
  else
  {
    snprintf(result, maxLen, "%d.%d.%d.%d", (addr & 0xFF), ((addr >> 8) & 0xFF), ((addr >> 16) & 0xFF), ((addr >> 24) & 0xFF));
  }
}

const char *GetPrintableProto(unsigned short proto)
{
  switch (proto)
  {
  case IPPROTO_IP:
    return printableProto[ALL];
  case IPPROTO_TCP:
    return printableProto[TCP];
  case IPPROTO_UDP:
    return printableProto[UDP];
  case IPPROTO_UDPLITE:
    return printableProto[UDPLITE];
  case IPPROTO_ICMP:
    return printableProto[ICMP];
  case IPPROTO_ICMPV6:
    return printableProto[ICMPV6];
  case IPPROTO_ESP:
    return printableProto[ESP];
  case IPPROTO_AH:
    return printableProto[AH];
  case IPPROTO_SCTP:
    return printableProto[SCTP];
  case IPPROTO_MH:
    return printableProto[MH];
  default:
    return printableProto[UNKNOWN];
  }
}

/*
 * Dummy ipt_entry will set dcsp value of tcp packets matching destination prt 1111 to 0x1A 
 */
const struct ipt_entry const *GetDummyIptEntry(unsigned short port)
{
  struct ipt_entry *e = NULL;
  unsigned int targetOffset = XT_ALIGN(sizeof(struct ipt_entry)) + XT_ALIGN(sizeof(struct ipt_entry_match)) + XT_ALIGN(sizeof(struct xt_tcp));
  unsigned int totalLen = targetOffset + (XT_ALIGN(sizeof(struct xt_entry_target)) + XT_ALIGN(sizeof(struct xt_DSCP_info)));
  e = (struct ipt_entry *)calloc(1, totalLen);
  if (e == NULL)
  {
    printf("calloc failure :%s\n", strerror(errno));
    return e;
  }

  e->target_offset = targetOffset;
  e->next_offset = totalLen;
  e->ip.proto = 6;
  e->ip.invflags = 0x0;

  struct ipt_entry_match *matchTcp = (struct ipt_entry_match *)((void *)e->elems + 0);
  struct xt_tcp *tcpInfo;

  struct xt_entry_target *dscpTarget = (struct xt_entry_target *)((void *)e->elems + XT_ALIGN(sizeof(struct ipt_entry_match)) + XT_ALIGN(sizeof(struct xt_tcp)));
  struct xt_DSCP_info *dscpInfo;

  matchTcp->u.match_size = XT_ALIGN(sizeof(struct ipt_entry_match)) + XT_ALIGN(sizeof(struct xt_tcp));
  strcpy(matchTcp->u.user.name, "tcp");
  tcpInfo = (struct xt_tcp *)matchTcp->data;
  tcpInfo->spts[0] = 0x0;
  tcpInfo->spts[1] = 0xFFFF;
  tcpInfo->dpts[0] = port;
  tcpInfo->dpts[1] = port;
  tcpInfo->invflags = 0x0000;

  dscpTarget->u.target_size = (XT_ALIGN(sizeof(struct xt_entry_target)) + XT_ALIGN(sizeof(struct xt_DSCP_info)));
  strcpy(dscpTarget->u.user.name, "DSCP");
  dscpTarget->u.user.revision = 0x0;
  dscpInfo = (struct xt_DSCP_info *)dscpTarget->data;
  dscpInfo->dscp = 0x1A;
  return e;
}
