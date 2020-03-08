#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <iptables.h>

const struct ipt_entry const *GetDummyIptEntry(unsigned short port);
const char *GetPrintableProto(unsigned short proto);
void GetPrintableIp(uint32_t addr, char *result, size_t maxLen);

#endif