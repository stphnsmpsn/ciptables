#include "Util.h"
#include "Ciptables.h"
#include "CommandParser.h"
#include "ServiceLocator/Iptables/Iptables.h"
#include "ServiceLocator/Iptables/IptablesImplementation.h"


int main(const int argc, const char const **argv)
{
  SetIptables(GetIptables);
  return processCommand(argc, argv);
}

