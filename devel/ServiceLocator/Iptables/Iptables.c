#include <stddef.h>

#include "Iptables.h"
#include "../Null/NullFunctions.h"

static IptablesInterface iptables = {
    .setup = (IptablesSetupFunctionPointer) NullReturnUninitialized,
    .teardown = (IptablesTeardownFunctionPointer) NullReturnUninitialized,
    .listTable = (IptablesListFunctionPointer)NullReturnUninitialized,
    .createChain = (IptablesCreateChainFunctionPointer)NullReturnUninitialized,
    .deleteChain = (IptablesDeleteChainFunctionPointer)NullReturnUninitialized,
    .appendRuleToChain = (IptablesAppendEntryToChainFunctionPointer)NullReturnUninitialized,
    .replaceRuleInChain = (IptablesReplaceRuleFunctionPointer)NullReturnUninitialized,
    .deleteRuleFromChain = (IptablesDeleteNumberInChainFunctionPointer)NullReturnUninitialized,
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