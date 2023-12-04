#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ptrace.h>

#include "ftrace.h"
#include "interface.h"

// See samples/kprobes/kprobe_example.c for examples
#define PRE_HANDLER_KERNEL(name, addr, size)   \
    static int __kprobes pre_##name (struct kprobe *p, struct pt_regs *regs) { \
        interface_write_to_kernel(addr, size);     \
        return 0;                                  \
    }

#define PRE_HANDLER_USER(name, addr, size)   \
    static int __kprobes pre_##name (struct kprobe *p, struct pt_regs *regs) { \
        interface_write_to_user(addr, size);     \
        return 0;                                \
    }

#ifdef CONFIG_X86
// The use of registers relies on the arch.
// arch/x86/lib/putuser.S
// arch/x86/lib/getuser.S
PRE_HANDLER_KERNEL(copy_from_user, regs->si, regs->dx)
PRE_HANDLER_KERNEL(get_user_1, regs->ax, 1)
PRE_HANDLER_KERNEL(get_user_2, regs->ax, 2)
PRE_HANDLER_KERNEL(get_user_4, regs->ax, 4)
PRE_HANDLER_KERNEL(get_user_8, regs->ax, 8)
PRE_HANDLER_USER(copy_to_user, regs->di, regs->dx)
PRE_HANDLER_USER(put_user_1, regs->cx, 1)
PRE_HANDLER_USER(put_user_2, regs->cx, 2)
PRE_HANDLER_USER(put_user_4, regs->cx, 4)
PRE_HANDLER_USER(put_user_8, regs->cx, 8)
#endif

static struct kprobe hooks[] = {
    HOOK_KPROBE("_copy_from_user", pre_copy_from_user, NULL),
    HOOK_KPROBE("__get_user_1", pre_get_user_1, NULL),
    HOOK_KPROBE("__get_user_2", pre_get_user_2, NULL),
    HOOK_KPROBE("__get_user_4", pre_get_user_4, NULL),
    HOOK_KPROBE("__get_user_8", pre_get_user_8, NULL),
    HOOK_KPROBE("_copy_to_user", pre_copy_to_user, NULL),
    HOOK_KPROBE("__put_user_1", pre_put_user_1, NULL),
    HOOK_KPROBE("__put_user_2", pre_put_user_2, NULL),
    HOOK_KPROBE("__put_user_4", pre_put_user_4, NULL),
    HOOK_KPROBE("__put_user_8", pre_put_user_8, NULL),
};

static int install_hooks(void) {
    size_t i;
    int err;
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        err = register_kprobe(&hooks[i]);
        if (err < 0) {
            printk("register_kprobe failed, returned %d\n", err);
            goto error;
        }
    }
    return 0;

error:
    while (i) {
        unregister_kprobe(&hooks[--i]);
    }
    return err;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Weiteng Chen");
MODULE_DESCRIPTION("interface hook using kprobe");
MODULE_VERSION("0.01");

static int __init hook_init(void) {
    int err = 0;
    err = install_hooks();
    if (err)
        return err;

    // Create a debugfs file for communication
    interface_init();
    printk("module hook loaded!\n");
    return 0;
}

static void __exit hook_exit(void) {
    size_t i;
    for (i = 0; i < ARRAY_SIZE(hooks); i++)
        unregister_kprobe(&hooks[i]);
    printk("module hook exits\n");
}

module_init(hook_init);
module_exit(hook_exit);