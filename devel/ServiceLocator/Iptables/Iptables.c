#include <stddef.h>

#include "Iptables.h"
#include "../Null/NullFunctions.h"

static IptablesInterface iptables = {
    .list = (IptablesFunctionPointer)NullReturnUninitialized,
    .add = (IptablesFunctionPointer)NullReturnUninitialized,
    .modify = (IptablesFunctionPointer)NullReturnUninitialized,
    .delete = (IptablesFunctionPointer)NullReturnUninitialized,
    .unsupported = (IptablesFunctionPointer)NullReturnUninitialized,
};


bool SetIptables(InitIptablesInterface init)
{
    if (init == NULL)
        return false;

    return init(&iptables);
}

IptablesInterface *Iptables(void)
{
    return &iptables;
}