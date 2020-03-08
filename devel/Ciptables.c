#include <stdlib.h>
#include "Util.h"
#include "Ciptables.h"
#include "CommandParser.h"
#include "ServiceLocator/Iptables/Iptables.h"
#include "ServiceLocator/Iptables/IptablesImplementation.h"

int main(const int argc, const char const **argv)
{
  printHeader();
  SetIptables(GetIptables); // Set Iptables interface to real implementation
  IptablesFunctionPointer cmd = parseCommand(argv[CMD_NAME_IDX]);
  cmd(argv);
}
