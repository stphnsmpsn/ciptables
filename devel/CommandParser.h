#ifndef COMMANDPARSER_H
#define COMMANDPARSER_H

#include "ServiceLocator/Iptables/Iptables.h"

IptablesFunctionPointer parseCommand(const char const *cmd);

#endif