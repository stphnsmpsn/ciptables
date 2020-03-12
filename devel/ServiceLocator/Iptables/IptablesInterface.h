#ifndef SERVICELOCATORIPTABLESINTERFACE_H
#define SERVICELOCATORIPTABLESINTERFACE_H

#include <libiptc/libiptc.h>

typedef int (*IptablesSetupFunctionPointer)();
typedef int (*IptablesTeardownFunctionPointer)();
typedef int (*IptablesListFunctionPointer)(const char const *tableName);
typedef int (*IptablesCreateChainFunctionPointer)(const char const *tableName, const char const *chainName);
typedef int (*IptablesDeleteChainFunctionPointer)(const char const *tableName, const char const *chainName);
typedef int (*IptablesAppendEntryToChainFunctionPointer)(const char const * tableName, const char const *chainName, const struct ipt_entry const * entry);
typedef int (*IptablesReplaceRuleFunctionPointer)(const char const * tableName, const char const *chainName, const struct ipt_entry const * entry, int num);
typedef int (*IptablesDeleteNumberInChainFunctionPointer)(const char const* tableName, const char const* chainName, const int num);

typedef struct {
    IptablesSetupFunctionPointer setup;
    IptablesTeardownFunctionPointer teardown;
    IptablesListFunctionPointer listTable;
    IptablesCreateChainFunctionPointer createChain;
    IptablesDeleteChainFunctionPointer deleteChain;
    IptablesAppendEntryToChainFunctionPointer appendRuleToChain;
    IptablesReplaceRuleFunctionPointer replaceRuleInChain;
    IptablesDeleteNumberInChainFunctionPointer deleteRuleFromChain;
} IptablesInterface;

#endif