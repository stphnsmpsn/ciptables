#ifndef SERVICELOCATORIPTABLESINTERFACE_H
#define SERVICELOCATORIPTABLESINTERFACE_H

#include <libiptc/libiptc.h>

typedef int (*IptablesListFunctionPointer)(const char const *tableName);
typedef int (*IptablesCreateChainFunctionPointer)(const char const *tableName, const char const *chainName);
typedef int (*IptablesDeleteChainFunctionPointer)(const char const *tableName, const char const *chainName);
typedef int (*IptablesAppendEntryToChainFunctionPointer)(const char const * table, const xt_chainlabel chainLabel, const struct ipt_entry const * entry);
typedef int (*IptablesReplaceRuleFunctionPointer)(const char const * table, const xt_chainlabel chainLabel, const struct ipt_entry const * entry, int num);
typedef int (*IptablesDeleteNumberInChainFunctionPointer)(const char const* table, const char const* chain, const int num);

typedef struct {
    IptablesListFunctionPointer listTable;
    IptablesCreateChainFunctionPointer createChain;
    IptablesDeleteChainFunctionPointer deleteChain;
    IptablesAppendEntryToChainFunctionPointer appendRuleToChain;
    IptablesReplaceRuleFunctionPointer replaceRuleInChain;
    IptablesDeleteNumberInChainFunctionPointer deleteRuleFromChain;
} IptablesInterface;

#endif