#ifndef SERVICELOCATORIPTABLESINTERFACE_H
#define SERVICELOCATORIPTABLESINTERFACE_H

typedef int (*IptablesFunctionPointer)(const char **argv);

typedef struct {
    IptablesFunctionPointer list;
    IptablesFunctionPointer add;
    IptablesFunctionPointer modify;
    IptablesFunctionPointer delete;
    IptablesFunctionPointer unsupported;
} IptablesInterface;

#endif