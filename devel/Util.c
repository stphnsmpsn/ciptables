#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
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

static const char* const printableProto[] = {
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
    "unknown"
};

const char *getProtocol(unsigned short proto)
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

void printHeader(){
  printf("*************************************************\r\n");
  printf("               steve's ciptables                \r\n");
  printf("*************************************************\r\n");
}