#ifndef SERVICELOCATORIPTABLES_H
#define SERVICELOCATORIPTABLES_H

#include <stdbool.h>
#include "IptablesInterface.h"

typedef bool (*InitIptablesInterface)(IptablesInterface *interface);

bool SetIptables(InitIptablesInterface init);
IptablesInterface* Iptables(void);

#endif 