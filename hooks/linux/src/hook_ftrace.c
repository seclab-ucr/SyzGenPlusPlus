
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "ftrace.h"

static void copy_from_user_callback(
    unsigned long ip, 
    unsigned long parent_ip,
    struct ftrace_ops *op, 
    struct ftrace_regs *regs
) {
    // if(!within_module(parent_ip, THIS_MODULE))
    printk("invoke callback");
    return;
}

// Cannot hook _copy_from_user cause it is written in assembly and
// thus does not have instrumentation.
static ftrace_hook_t hooks[] = {
    HOOK("_copy_from_user", copy_from_user_callback),
};

static void uninstall_hook(ftrace_hook_t *hook) {
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        printk("unregister_ftrace_function for %s failed: %d\n", hook->name, err);
    }
    err = ftrace_set_filter(&hook->ops, NULL, 0, 1);
    if (err) {
        printk("remove ftrace_set_filter for %s failed: %d\n", hook->name, err);
    }
}

static int install_hooks(void) {
    int err;
    size_t i;
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        ftrace_hook_t *hook = &hooks[i];
        hook->address = kallsyms_lookup_name_func(hook->name);
        printk("hook %s 0x%lx\n", hook->name, hook->address&0xffffffff);
        if (hook->address == 0) {
            printk("unresolved symbol: %s\n", hook->name);
            err = -ENOENT;
            break;
        }
        err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
        if (err) {
            printk("ftrace_set_filter_ip for %s failed: %d\n", hook->name, err);
            break;
        }
        err = register_ftrace_function(&hook->ops);
        if (err) {
            printk("register_ftrace_function for %s failed: %d\n", hook->name, err);
            break;
        }
    }

    if (err) {
        while (i) {
            uninstall_hook(&hooks[--i]);
        }
    }
    return err;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Weiteng Chen");
MODULE_DESCRIPTION("interface hook using ftrace");
MODULE_VERSION("0.01");

static int __init interface_init(void) {
    int err;
    printk("module interface init");
    err = init_kallsyms();
    if (err) {
        printk("failed to find kallsyms_lookup_name: %d", err);
        return err;
    }
    printk("find kallsyms_lookup_name address at %p\n", kallsyms_lookup_name_func);

    err = install_hooks();
    if (err)
        return err;
    printk("module interface loaded!\n");
    return 0;
}

static void __exit interface_exit(void) {
    size_t i;
    printk("module interface exit");
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        uninstall_hook(&hooks[i]);
    }
}

module_init(interface_init);
module_exit(interface_exit);