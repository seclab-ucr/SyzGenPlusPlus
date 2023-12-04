
#ifndef FTRACE_HEADER_H
#define FTRACE_HEADER_H

#include <linux/ftrace.h>
#include <linux/kprobes.h>

typedef struct ftrace_hook {
    char *name;
    unsigned long address;
    struct ftrace_ops ops;
} ftrace_hook_t;

#define HOOK(_name, _hook) \
{                          \
    .name = _name,         \
    .ops = {               \
        .func  = _hook,    \
        .flags = FTRACE_OPS_FL_SAVE_REGS|FTRACE_OPS_FL_RECURSION,  \
    }                      \
}

#define HOOK_KPROBE(_name, _pre_hook, _post_hook) \
{                               \
    .symbol_name = _name,       \
    .pre_handler = _pre_hook,   \
    .post_handler = _post_hook, \
}

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func = NULL;
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

int init_kallsyms(void) {
    int err = register_kprobe(&kp);
    if (err)
        return err;
    kallsyms_lookup_name_func = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    return 0;
}
#endif