#ifndef HOOK_HEADER_H
#define HOOK_HEADER_H

#define INTERFACE_NAME "hook"
#define INTERFACE_PATH "/sys/kernel/debug/hook"
#define HOOK_ENABLE     _IO('c', 100)
#define HOOK_DISABLE    _IO('c', 101)
#define HOOK_INIT       _IOR('c', 1, unsigned long)
#define HOOK_TEST       _IO('c', 111)
#define HOOK_FD         _IO('c', 112)

#define COPY_FROM_USER  1
#define COPY_TO_USER    2

#pragma pack(8)

typedef struct hook_entry {
    unsigned long addr;
    unsigned size;
    unsigned id;
} hook_entry_t __attribute__ ((aligned (8)));

int compare_entry(const void *a, const void *b) {
    hook_entry_t *h1 = (hook_entry_t *)a;
    hook_entry_t *h2 = (hook_entry_t *)b;
    return h1->addr - h2->addr;
}

// struct fd f = fdget(fd);
// struct file file = f.file
// struct file_operations ops = file.f_op
// See all operations in struct file_operations
typedef struct fd_operations {
    unsigned long fd;
    unsigned long read;
    unsigned long write;
    unsigned long unlocked_ioctl;
    unsigned long compat_ioctl;
    unsigned long open;
} fd_operations_t;

#ifndef ALIGN
#define _ALIGN(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN(x, a) _ALIGN(x, (typeof(x))(a) - 1)
#endif

#define SIZE_OF_HOOK(size) ALIGN(((size) * sizeof(hook_entry_t) + sizeof(unsigned long)), 4096)
#define GET_HOOK_ENTRIES(ptr) (hook_entry_t*)((uint8_t*)(ptr) + sizeof(unsigned long))

#endif