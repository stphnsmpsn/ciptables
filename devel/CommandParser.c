#include <string.h>
#include "CommandParser.h"

#define CMD_LIST "list"
#define CMD_ADD "add"
#define CMD_MODIFY "modify"
#define CMD_DELETE "delete"

IptablesFunctionPointer parseCommand(const char const *cmd)
{
    if (strcmp(cmd, CMD_LIST) == 0)
    {
        return Iptables()->list;
    }
    else if (strcmp(cmd, CMD_ADD) == 0)
    {
        return Iptables()->add;
    }
    else if (strcmp(cmd, CMD_MODIFY) == 0)
    {
        return Iptables()->modify;
    }
    else if (strcmp(cmd, CMD_DELETE) == 0)
    {
        return Iptables()->delete;
    }
    else /* default: */
    {
        return Iptables()->unsupported;
    }
}