#include <stdio.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>
#include <iptables.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter/xt_limit.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/xt_dscp.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_RATEEST.h>
#include <linux/netfilter/xt_rateest.h>
#include <linux/netfilter/xt_DSCP.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/x_tables.h>
#include <netinet/in.h>
#include <unistd.h>
#include "Iptables.h"
#include "../../Ciptables.h"
#include "../../Util.h"

static void PrintChainHeader(const char const *chain, const char const *policy);
static void PrintRule(int num, const char *target, const struct ipt_entry *entry);
static bool ValidateHandle(struct xtc_handle *xHandle);

static int ListTable(const char const *tableName)
{
    struct xtc_handle *xHandle = iptc_init(tableName);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    const char *chain;
    const struct ipt_entry *entry;
    const char *policy;
    struct xt_counters counter;
    int ruleNum;

    chain = iptc_first_chain(xHandle);
    while (chain)
    {
        policy = iptc_get_policy(chain, &counter, xHandle);
        PrintChainHeader(chain, policy);
        entry = iptc_first_rule(chain, xHandle);
        ruleNum = 0;
        while (entry)
        {
            ruleNum++;
            const char *target = iptc_get_target(entry, xHandle);
            PrintRule(ruleNum, target, entry);
            entry = iptc_next_rule(entry, xHandle);
        }
        chain = iptc_next_chain(xHandle);
        printf("\r\n");
    }
    iptc_free(xHandle);
    return SUCCESS;
}

static int CreateChain(const char const *tableName, const char const *chainName)
{
    struct xtc_handle *xHandle = iptc_init(tableName);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    iptc_create_chain(chainName, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);
    return SUCCESS;
}

static int DeleteChain(const char const *tableName, const char const *chainName)
{
    struct xtc_handle *xHandle = iptc_init(tableName);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    iptc_delete_chain(chainName, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);
    return SUCCESS;
}

static void PrintChainHeader(const char const *chain, const char const *policy)
{
    printf("Chain %s", chain);
    if (policy != NULL)
        printf("(policy %s)", policy);
    printf("\r\n");
    printf("num target                   prot opt source          destination\r\n");
}

static void PrintRule(int num, const char *target, const struct ipt_entry *entry)
{
    char srcStr[64];
    char dstStr[64];
    GetPrintableIp(entry->ip.src.s_addr, srcStr, sizeof(srcStr));
    GetPrintableIp(entry->ip.dst.s_addr, dstStr, sizeof(dstStr));
    printf("%-3d %-24s %s  --  %s        %s\r\n", num, target, GetPrintableProto(entry->ip.proto), srcStr, dstStr);
}

static int AppendRuleToChain(const char const *table, const xt_chainlabel chainLabel, const struct ipt_entry const *entry)
{
    struct xtc_handle *xHandle = iptc_init(table);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    iptc_append_entry(chainLabel, entry, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);
    return SUCCESS;
}

static int ReplaceRuleInChain(const char const *table, const xt_chainlabel chainLabel, const struct ipt_entry const *entry, int num)
{
    struct xtc_handle *xHandle = iptc_init(table);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }
    iptc_replace_entry(chainLabel, entry, num, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);
    return SUCCESS;
}

/* This is only being used as my kernel was not compatible with the other method and I did not have time to modify it. 
 * Please see Delete() below for how I would really implement a delete by number in chain method
 */
static int MvpDeleteNumberInChain(const char const *table, const char const *chain, const int num)
{
    struct xtc_handle *xHandle = iptc_init(table);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    const char *c;
    const struct ipt_entry *e;

    c = iptc_first_chain(xHandle);
    while (c)
    {
        if (strcmp(c, chain) == 0)
        {
            e = iptc_first_rule(c, xHandle);
            int n = 0;
            while (e)
            {
                n++;
                const char *target = iptc_get_target(e, xHandle);
                if (n == num)
                {
                    iptc_delete_entry(c, e, (unsigned char *)target, xHandle);
                    iptc_commit(xHandle);
                    goto end;
                }
                e = iptc_next_rule(e, xHandle);
            }
        }
        c = iptc_next_chain(xHandle);
    }
end:
    iptc_free(xHandle);
    return SUCCESS;
}

static int DeleteNumberInChain(const char const *table, const char const *chain, const int num)
{
    struct xtc_handle *xHandle = iptc_init(table);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    iptc_delete_num_entry(chain, num, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);
    return SUCCESS;
}

bool GetIptables(IptablesInterface *interface)
{
    if (interface == NULL)
        return false;

    interface->listTable = (IptablesListFunctionPointer)ListTable;
    interface->createChain = (IptablesCreateChainFunctionPointer)CreateChain;
    interface->deleteChain = (IptablesDeleteChainFunctionPointer)DeleteChain;
    interface->appendRuleToChain = (IptablesAppendEntryToChainFunctionPointer)AppendRuleToChain;
    interface->replaceRuleInChain = (IptablesReplaceRuleFunctionPointer)ReplaceRuleInChain;
    interface->deleteRuleFromChain = (IptablesDeleteNumberInChainFunctionPointer)MvpDeleteNumberInChain;

    return true;
}

static bool ValidateHandle(struct xtc_handle *xHandle)
{
    if (!xHandle)
    {
        printf("Error Condition:  %s\r\n", iptc_strerror(errno));
        return false;
    }
    else
    {
        return true;
    }
}