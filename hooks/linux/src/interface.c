
#include <linux/debugfs.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/file.h>

#include "interface.h"
#include "hook.h"

struct hook {
    spinlock_t lock;
    void *data;
    unsigned int size;
    unsigned int pid;
    enum hook_mode mode;
} ghook;

void interface_write(unsigned long addr, unsigned size, unsigned func_id) {
    hook_entry_t *entries;
    unsigned long *data;
    unsigned long pos;
    
    if (ghook.mode != HOOK_MODE_ENABLED || current->pid != ghook.pid)
        return;

    entries = (hook_entry_t*)((uint8_t*)ghook.data + sizeof(unsigned long));
    data = (unsigned long*)ghook.data;
    pos = READ_ONCE(data[0]);
    if (likely(pos < ghook.size)) {
        entries[pos].addr = addr;
        entries[pos].size = size;
        entries[pos].id = func_id;
        WRITE_ONCE(data[0], pos+1);
    }
}

void interface_write_to_user(unsigned long addr, unsigned size) {
    interface_write(addr, size, COPY_TO_USER);
}

void interface_write_to_kernel(unsigned long addr, unsigned size) {
    interface_write(addr, size, COPY_FROM_USER);
}

static void reset_hook(struct hook* hook) {
    unsigned long* data = (unsigned long*)hook->data;
    WRITE_ONCE(data[0], 0);
}

static int interface_open(struct inode *inode, struct file *filep) {
    unsigned long flags;
    int res = 0;
    spin_lock_irqsave(&ghook.lock, flags);
    if (ghook.mode != HOOK_MODE_DETACHED) {
        res = -EBUSY;
        goto exit;
    }
    ghook.mode = HOOK_MODE_ATTACHED;
    res = nonseekable_open(inode, filep);

exit:
    spin_unlock_irqrestore(&ghook.lock, flags);
    return res;
}

static int interface_close(struct inode *inode, struct file *filep) {
    if (ghook.data) {
        vfree(ghook.data);
        ghook.data = NULL;
    }
    ghook.mode = HOOK_MODE_DETACHED;
    return 0;
}

static int interface_mmap(struct file *filep, struct vm_area_struct *vma) {
    int res = 0;
    void *data;
    unsigned long flags;
    unsigned long size, off;
    struct page *page;
    struct hook *hook = &ghook;

    // printk("call interface_mmap %d, %d, %lu\n", 
    //     hook->mode, hook->size, vma->vm_end - vma->vm_start);
    data = vmalloc_user(vma->vm_end - vma->vm_start);
    if (!data)
        return -ENOMEM;
    spin_lock_irqsave(&hook->lock, flags);
    size = SIZE_OF_HOOK(hook->size);
    if (hook->mode != HOOK_MODE_DISABLED || vma->vm_pgoff != 0 ||
        vma->vm_end - vma->vm_start != size) {
            printk("invalid input %lu\n", size);
            res = -EINVAL;
            goto exit;
    }
    if (!hook->data) {
        hook->data = data;
        vma->vm_flags |= VM_DONTEXPAND;
        spin_unlock_irqrestore(&hook->lock, flags);
        for (off = 0; off < size; off += PAGE_SIZE) {
            page = vmalloc_to_page(hook->data + off);
            if (vm_insert_page(vma, vma->vm_start + off, page))
                pr_info("vm_insert_page failed\n");
        }
        return 0;
    }
exit:
    spin_unlock_irqrestore(&hook->lock, flags);
    vfree(data);
    return res;
}

static int interface_get_fd(unsigned long arg) {
    fd_operations_t ops;
    struct fd f;

    if(copy_from_user(&ops, (const void*)arg, sizeof(ops))) {
        return -EINVAL;
    }

    if (ops.fd <= 2) // reserved fd
        return -EBADF;

    f = fdget(ops.fd);
    if (!f.file)
        return -EBADF;

    ops.open = (unsigned long)f.file->f_op->open;
    ops.read = (unsigned long)f.file->f_op->read;
    ops.write = (unsigned long)f.file->f_op->write;
    ops.unlocked_ioctl = (unsigned long)f.file->f_op->unlocked_ioctl;
    ops.compat_ioctl = (unsigned long)f.file->f_op->compat_ioctl;
    return copy_to_user((void *)arg, &ops, sizeof(ops));
}

static int interface_test(unsigned long arg) {
    int value;
    return copy_from_user(&value, (const void *)arg, sizeof(value));
}

static int interface_ioctl_locked(struct hook *hook, unsigned int cmd, unsigned long arg) {
    unsigned long size;

    switch (cmd)
    {
    case HOOK_INIT:
        if (hook->mode != HOOK_MODE_ATTACHED)
            return -EBUSY;

        size = arg;
        if (size < 2 || size > INT_MAX / sizeof(unsigned long))
            return -EINVAL;
        hook->size = size;
        hook->mode = HOOK_MODE_DISABLED;
        return 0;
    case HOOK_ENABLE:
        if (hook->mode != HOOK_MODE_DISABLED || !hook->data)
            return -EINVAL;
        reset_hook(hook);
        hook->pid = current->pid;
        hook->mode = HOOK_MODE_ENABLED;
        return 0;
    case HOOK_DISABLE:
        if (hook->mode != HOOK_MODE_ENABLED && hook->mode != HOOK_MODE_DISABLED)
            return -EINVAL;
        hook->mode = HOOK_MODE_DISABLED;
        return 0;
    case HOOK_TEST:
        return interface_test(arg);
    default:
        return -ENOTTY;
    }
}

static long interface_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    int res;
    unsigned long flags;
    // printk("call interface_ioctl with cmd: %d\n", cmd);
    if (cmd == HOOK_FD) {
        // no need for lock as no multi-threading occurs for this
        return interface_get_fd(arg);
    }
    spin_lock_irqsave(&ghook.lock, flags);
    res = interface_ioctl_locked(&ghook, cmd, arg);
    spin_unlock_irqrestore(&ghook.lock, flags);
    return res;
}

static const struct file_operations interface_fops = {
    .open           = interface_open,
    .unlocked_ioctl = interface_ioctl,
    .compat_ioctl   = interface_ioctl,
    .mmap           = interface_mmap,
    .release        = interface_close,
};

int interface_init(void) {
    ghook.mode = HOOK_MODE_DETACHED;
    ghook.data = NULL;
    spin_lock_init(&ghook.lock);

    debugfs_create_file_unsafe(INTERFACE_NAME, 0600, NULL, NULL, &interface_fops);
    return 0;
}