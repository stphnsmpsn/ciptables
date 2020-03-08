#include <stdio.h>
#include "Iptables.h"
#include "../../Ciptables.h"
#include "../../Util.h"

int list(const char **argv)
{
    printf("LISTING\r\n");
    return ERROR_NOT_IMPLEMENTED;
}

static int add(const char **argv)
{
    printf("ADDING\r\n");
    return ERROR_NOT_IMPLEMENTED;
}

static int modify(const char **argv)
{
    printf("MODIFYING\r\n");
    return ERROR_NOT_IMPLEMENTED;
}

static int delete (const char **argv)
{
    printf("DELETING\r\n");
    return ERROR_NOT_IMPLEMENTED;
}

static int unsupported(const char **argv)
{
    printf("Unsupported Command\r\n");
    return ERROR_UNSUPPORTED_OPERATION;
}

bool GetIptables(IptablesInterface *interface)
{
    if (interface == NULL)
        return false;

    interface->list = (IptablesFunctionPointer)list;
    interface->add = (IptablesFunctionPointer)add;
    interface->modify = (IptablesFunctionPointer)modify;
    interface->delete = (IptablesFunctionPointer) delete;
    interface->unsupported = (IptablesFunctionPointer)unsupported;

    return true;
}