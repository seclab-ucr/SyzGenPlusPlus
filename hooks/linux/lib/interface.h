
#ifndef INTERFACE_HEADER_H
#define INTERFACE_HEADER_H

enum hook_mode {
    HOOK_MODE_DETACHED  = 0,
    HOOK_MODE_ATTACHED  = 1,
    HOOK_MODE_DISABLED  = 2,
    HOOK_MODE_ENABLED   = 3,
};

int interface_init(void);
void interface_write_to_user(unsigned long addr, unsigned size);
void interface_write_to_kernel(unsigned long addr, unsigned size);

#endif