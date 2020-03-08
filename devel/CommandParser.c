#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "Ciptables.h"
#include "CommandParser.h"
#include "Util.h"



int RunDemo();

int processCommand(const int argc, const char const **argv)
{

    // Lists all rules in each chain for the specified table
    if (strcmp(argv[CMD_NAME_IDX], CMD_LIST_TABLE) == 0)
    {
        return Iptables()->listTable(argv[CMD_LIST_TABLE_IDX]);
    }

    // create the specified chain in the specified table (if it does not exist)
    if (strcmp(argv[CMD_NAME_IDX], CMD_CREATE_CHAIN) == 0)
    {
        return Iptables()->createChain(argv[CMD_CREATE_CHAIN_TABLE_IDX], argv[CMD_CREATE_CHAIN_CHAIN_IDX]);
    }

    // delete the specified chain in the specified table
    if (strcmp(argv[CMD_NAME_IDX], CMD_DELETE_CHAIN) == 0)
    {
        return Iptables()->deleteChain(argv[CMD_DELETE_CHAIN_TABLE_IDX], argv[CMD_DELETE_CHAIN_CHAIN_IDX]);
    }

    // Adds a dummy rule to the specified chain of the specified table
    else if (strcmp(argv[CMD_NAME_IDX], CMD_APPEND_RULE) == 0)
    {
        return Iptables()->appendRuleToChain(argv[CMD_APPEND_RULE_TABLE_IDX], argv[CMD_APPEND_RULE_CHAIN_IDX], GetDummyIptEntry(atoi(argv[CMD_APPEND_RULE_PORT_IDX])));
    }

    // Adds a dummy rule to the specified chain of the specified table
    else if (strcmp(argv[CMD_NAME_IDX], CMD_REPLACE_RULE) == 0)
    {
        return Iptables()->replaceRuleInChain(argv[CMD_REPLACE_RULE_TABLE_IDX], argv[CMD_REPLACE_RULE_CHAIN_IDX], GetDummyIptEntry(atoi(argv[CMD_REPLACE_RULE_PORT_IDX])), atoi(argv[CMD_REPLACE_RULE_NUM_IDX]));
    }

    // Deletes the specified rule number from the specified chain in the specified table
    else if (strcmp(argv[CMD_NAME_IDX], CMD_DELETE_RULE) == 0)
    {
        return Iptables()->deleteRuleFromChain(argv[CMD_DELETE_RULE_TABLE_IDX], argv[CMD_DELETE_RULE_CHAIN_IDX], atoi(argv[CMD_DELETE_RULE_NUM_IDX]));
    }

    // Run demonstration
    else if (strcmp(argv[CMD_NAME_IDX], CMD_DEMO) == 0)
    {
        return RunDemo();
    }

    else /* default: */
    {
        printf("Unsupported Operation\r\n");
        return ERROR_UNSUPPORTED_OPERATION;
    }
}

int RunDemo()
{
    const char const *table = "mangle";
    const char const *chain = "TEST";
    unsigned short port = 1600;

    printf("\r\nStep 1: Listing `%s` Table...\r\n\n", table);
    Iptables()->listTable(table);

    printf("Step 2: Creating `%s` chain in `%s` Table...\r\n", chain, table);
    Iptables()->createChain(table, chain);

    printf("\r\nStep 3: Listing `%s` Table (you should see a new '%s' chain)...\r\n\n", table, chain);
    Iptables()->listTable(table);

    printf("Step 4: Appending Dummy Rule to '%s' Chain in `%s` Table...\r\n", chain, table);
    Iptables()->appendRuleToChain(table, chain, GetDummyIptEntry(port));

    printf("\r\nStep 5: Listing `%s` Table (you should see a new rule in the `%s` chain)...\r\n\n", table, chain);
    Iptables()->listTable(table);

    printf("Step 6: Deleting Rule from the `%s` chain in `%s` Table...\r\n", chain, table);
    Iptables()->deleteRuleFromChain(table, chain, 1);

    printf("\r\nStep 7: Listing `%s` Table (you should see one less rule in the `%s` chain)...\r\n\n", table, chain);
    Iptables()->listTable(table);

    printf("Step 8: Deleting `%s` chain from `%s` Table...\r\n", chain, table);
    Iptables()->deleteChain(table, chain);

    printf("\r\nStep 9: Listing `%s` Table (you should see one chain in the table)...\r\n\n", table);
    Iptables()->listTable(table);
}