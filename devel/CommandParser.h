#ifndef COMMANDPARSER_H
#define COMMANDPARSER_H

#include "ServiceLocator/Iptables/Iptables.h"

#define CMD_LIST_TABLE "lt"
#define CMD_CREATE_CHAIN "cc"
#define CMD_DELETE_CHAIN "dc"
#define CMD_APPEND_RULE "ar"
#define CMD_REPLACE_RULE "rr"
#define CMD_DELETE_RULE "dr"
#define CMD_DEMO "rundemo"

#define CMD_NAME_IDX 1

#define CMD_LIST_NUM_ARGS 1
#define CMD_LIST_TABLE_IDX 2

#define CMD_CREATE_CHAIN_NUM_ARGS 2
#define CMD_CREATE_CHAIN_TABLE_IDX 2
#define CMD_CREATE_CHAIN_CHAIN_IDX 3

#define CMD_DELETE_CHAIN_NUM_ARGS 2
#define CMD_DELETE_CHAIN_TABLE_IDX 2
#define CMD_DELETE_CHAIN_CHAIN_IDX 3

#define CMD_APPEND_RULE_NUM_ARGS 3
#define CMD_APPEND_RULE_TABLE_IDX 2
#define CMD_APPEND_RULE_CHAIN_IDX 3
#define CMD_APPEND_RULE_PORT_IDX 4

#define CMD_REPLACE_RULE_NUM_ARGS 4
#define CMD_REPLACE_RULE_TABLE_IDX 2
#define CMD_REPLACE_RULE_CHAIN_IDX 3
#define CMD_REPLACE_RULE_PORT_IDX 4
#define CMD_REPLACE_RULE_NUM_IDX 5

#define CMD_DELETE_RULE_NUM_ARGS 3
#define CMD_DELETE_RULE_TABLE_IDX 2
#define CMD_DELETE_RULE_CHAIN_IDX 3
#define CMD_DELETE_RULE_NUM_IDX 4

#define CMD_DEMO_NUM_ARGS 0

int ProcessCommand(const int argc, const char const **argv);

#endif