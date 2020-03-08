#include <stdlib.h>
#include "../Null/NullFunctions.h"
#include "Iptables.h"

bool GetNullIptables(IptablesInterface *interface)
{
    if (interface == NULL)
        return false;

    interface->list = (IptablesFunctionPointer)NullReturnUninitialized;
    interface->add = (IptablesFunctionPointer)NullReturnUninitialized;
    interface->modify = (IptablesFunctionPointer)NullReturnUninitialized;
    interface->delete = (IptablesFunctionPointer)NullReturnUninitialized;
    interface->unsupported = (IptablesFunctionPointer)NullReturnUninitialized;

    return true;
}