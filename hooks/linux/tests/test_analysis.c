
// compile:
// gcc -o test -Ilib/ tests/test_analysis.c 
#include <stdio.h>
#include <sys/mman.h>
#include "driver.h"

hook_entry_t entries[3] = {
    { .addr = 0x200010c0, .size = 8, .id = COPY_FROM_USER },
    { .addr = 0x200010c8, .size = 24, .id = COPY_FROM_USER },
    { .addr = 0x20001080, .size = 4, .id = COPY_TO_USER },
};

int main(int argc, char **argv) {
    printf("testing structure recovery...\n");
    void *addr = mmap((void *)0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
    if (addr == MAP_FAILED) {
        perror("failed to call mmap");
        return 1;
    }

    *(unsigned long *)0x200010c8 = 0x20001080;
    qsort(entries, 3, sizeof(hook_entry_t), compare_entry);
    for (int i = 0; i < 3; i++) {
        printf("addr: 0x%lx, size: %d, func id: %d\n", 
            entries[i].addr, entries[i].size, entries[i].id);
    }
    base_t *ptr = analyze_layout(0x200010c0, entries, 3);
    show_type(ptr);
    printf("\n");
    return 0;
}