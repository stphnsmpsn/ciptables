#include <stdlib.h>
#include "../Null/NullFunctions.h"
#include "Iptables.h"

bool GetNullIptables(IptablesInterface *interface)
{
    if (interface == NULL)
        return false;

    interface->setup = (IptablesSetupFunctionPointer) NullReturnUninitialized,
    interface->teardown = (IptablesTeardownFunctionPointer) NullReturnUninitialized,
    interface->listTable = (IptablesListFunctionPointer)NullReturnUninitialized;
    interface->createChain = (IptablesCreateChainFunctionPointer)NullReturnUninitialized;
    interface->deleteChain = (IptablesDeleteChainFunctionPointer)NullReturnUninitialized;
    interface->appendRuleToChain = (IptablesAppendEntryToChainFunctionPointer)NullReturnUninitialized;
    interface->replaceRuleInChain = (IptablesReplaceRuleFunctionPointer)NullReturnUninitialized;
    interface->deleteRuleFromChain = (IptablesDeleteNumberInChainFunctionPointer)NullReturnUninitialized;

    return true;
}