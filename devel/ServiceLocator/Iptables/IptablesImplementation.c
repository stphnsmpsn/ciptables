#include <sqlite3.h>
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

#define MAX_STATEMENT_LENGTH 1024 // made up value for now
static const char const *databaseName = "iptables.db";

static void PrintChainHeader(const char const *chainName, const char const *policy);
static void PrintRule(int num, const char *target, const struct ipt_entry *entry);
static bool ValidateHandle(struct xtc_handle *xHandle);
static int InitDatabase();
static int ExecuteSqlStmt(char *sql);
static void ClearSqlBuffer();

static sqlite3 *db;
static bool open = false;
static char sql[MAX_STATEMENT_LENGTH];

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

    // todo: error handling
    iptc_create_chain(chainName, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);

    // build and execute SQL statement
    snprintf(sql, sizeof(sql), ";");
    ExecuteSqlStmt(sql);

    return SUCCESS;
}

static int DeleteChain(const char const *tableName, const char const *chainName)
{
    struct xtc_handle *xHandle = iptc_init(tableName);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    // todo: error handling
    iptc_delete_chain(chainName, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);

    // build and execute SQL statement
    snprintf(sql, sizeof(sql), ";");
    ExecuteSqlStmt(sql);

    return SUCCESS;
}

static void PrintChainHeader(const char const *chainName, const char const *policy)
{
    printf("Chain %s", chainName);
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

static int AppendRuleToChain(const char const *tableName, const char const *chainName, const struct ipt_entry const *entry)
{
    struct xtc_handle *xHandle = iptc_init(tableName);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    iptc_append_entry(chainName, entry, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);

    // build and execute SQL statement
    snprintf(sql, sizeof(sql), ";");
    ExecuteSqlStmt(sql);

    return SUCCESS;
}

static int ReplaceRuleInChain(const char const *tableName, const char const *chainName, const struct ipt_entry const *entry, int num)
{
    struct xtc_handle *xHandle = iptc_init(tableName);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }
    iptc_replace_entry(chainName, entry, num, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);

    // build and execute SQL statement
    snprintf(sql, sizeof(sql), ";");
    ExecuteSqlStmt(sql);

    return SUCCESS;
}

/* This is only being used as my kernel was not compatible with the other method and I did not have time to modify it. 
 * Please see Delete() below for how I would really implement a delete by number in chain method
 */
static int MvpDeleteNumberInChain(const char const *tableName, const char const *chainName, const int num)
{
    struct xtc_handle *xHandle = iptc_init(tableName);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    const char *c;
    const struct ipt_entry *e;

    c = iptc_first_chain(xHandle);
    while (c)
    {
        if (strcmp(c, chainName) == 0)
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
                        // build and execute SQL statement
                        snprintf(sql, sizeof(sql), ";");
                        ExecuteSqlStmt(sql);
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

static int DeleteNumberInChain(const char const *tableName, const char const *chainName, const int num)
{
    struct xtc_handle *xHandle = iptc_init(tableName);

    if (!ValidateHandle(xHandle))
    {
        return errno;
    }

    iptc_delete_num_entry(chainName, num, xHandle);
    iptc_commit(xHandle);
    iptc_free(xHandle);

    // build and execute SQL statement
    snprintf(sql, sizeof(sql), ";");
    ExecuteSqlStmt(sql);

    return SUCCESS;
}

static int Setup()
{
    int result;
    if (!open)
    {
        result = sqlite3_open(databaseName, &db);
        if (result == SQLITE_OK)
        {
            open = true;
            result = InitDatabase();
        }
    }
    else
    {
        result = ERROR_GENERIC_ERROR; // todo: replace w/more detailed error
    }
    return result;
}

static int InitDatabase()
{
    int result;
    char *err_msg = 0;
    char *sql = ""; // Create initial DB structure (if it does not exist)
    // this means creating a table for the iptables (filter, nat, mangle, raw, and security)
    // and a filter for the chains. Chains table should have a foreign key tying the entry to an iptable


    result = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (result != SQLITE_OK)
    {

        fprintf(stderr, "SQL error: %s\n", err_msg);

        sqlite3_free(err_msg);
        sqlite3_close(db);

        return 1;
        return result;
    }
}

static int Teardown()
{
    int result;
    if (open)
    {
        result = sqlite3_close(db);
        if (result == SQLITE_OK)
        {
            open = false;
        }
    }
    else
    {
        result = ERROR_GENERIC_ERROR; // todo: replace w/more detailed error
    }
    return result;
}

bool GetIptables(IptablesInterface *interface)
{
    if (interface == NULL)
        return false;

    interface->setup = (IptablesSetupFunctionPointer)Setup;
    interface->teardown = (IptablesTeardownFunctionPointer)Teardown;
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

static int ExecuteSqlStmt(char *sql)
{
    char *err = 0;
    int rc = sqlite3_exec(db, sql, 0, 0, &err);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL Error: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
    }

    ClearSqlBuffer();
    return rc;
}

static void ClearSqlBuffer()
{
    memset(sql, 0, sizeof(sql));
}