#include <stdio.h>
#include "NullFunctions.h"
#include "../../Ciptables.h"

int NullReturnUninitialized(const char **argv){
    printf("method unitialized\r\n");
    return ERROR_UNINITIALIZED;
}