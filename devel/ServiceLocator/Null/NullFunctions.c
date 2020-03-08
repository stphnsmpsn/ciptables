#include <stdio.h>
#include "NullFunctions.h"
#include "../../Ciptables.h"

int NullReturnUninitialized(void){
    printf("method unitialized\r\n");
    return ERROR_UNINITIALIZED;
}