#ifndef SYZGEN_DRIVER_HEADER_H
#define SYZGEN_DRIVER_HEADER_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include "hook.h"
#include "type.h"

#define HOOK_SIZE (511)

static int driver_fd = -1;
static void *data = NULL;

int init_driver() {
    driver_fd = open(INTERFACE_PATH, O_RDWR);
    if (driver_fd == -1) {
        perror("open");
        return 1;
    }
    if (ioctl(driver_fd, HOOK_INIT, HOOK_SIZE)) {
        perror("ioctl");
        return 1;
    }
    data = mmap(NULL, SIZE_OF_HOOK(HOOK_SIZE), PROT_READ | PROT_WRITE, MAP_SHARED, driver_fd, 0);
    if (data == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    return 0;
}

int enable_driver() {
    if (driver_fd == -1) {
        printf("driver_fd: %d\n", driver_fd);
        return 1;
    }
    if (ioctl(driver_fd, HOOK_ENABLE, 0)) {
        perror("ioctl enable");
        return 1;
    }
    return 0;
}

int disable_driver() {
    if (driver_fd == -1) {
        printf("driver_fd: %d\n", driver_fd);
        return 1;
    }
    if (ioctl(driver_fd, HOOK_DISABLE, 0)) {
        perror("ioctl disable");
        return 1;
    }
    return 0;
}

int close_driver() {
    if (data) {
        if (munmap(data, SIZE_OF_HOOK(HOOK_SIZE))) {
            perror("munmap");
            return 1;
        }
        data = NULL;
    }
    
    if (driver_fd != -1) {
        if (close(driver_fd)) {
            perror("close");
            return 1;
        }
        driver_fd = -1;
    }
    return 0;
}

void print_driver() {
    unsigned long n, i;
    hook_entry_t *entries;

    if (!data)
        return;

    n = *(unsigned long*)data;
    entries = GET_HOOK_ENTRIES(data);
    for (i = 0; i < n; i++) {
        printf("addr: 0x%lx, size: %d, func id: %d\n", 
            entries[i].addr, entries[i].size, entries[i].id);
    }
}

int analyze_driver(unsigned long arg) {
    unsigned long n, i;
    hook_entry_t *entries;

    if (!data)
        return 1;

    n = *(unsigned long*)data;
    entries = GET_HOOK_ENTRIES(data);
    for (i = 0; i < n; i++) {
        printf("addr: 0x%lx, size: %d, func id: %d\n", 
            entries[i].addr, entries[i].size, entries[i].id);
    }

    qsort(entries, n, sizeof(hook_entry_t), compare_entry);
    base_t *ptr = analyze_layout(arg, entries, n);
    show_type(ptr);
    printf("\n");
    return 0;
}

void test_driver() {
    int val = 0;
    if (driver_fd == -1) {
        printf("driver_fd: %d\n", driver_fd);
        return;
    }
    ioctl(driver_fd, HOOK_TEST, &val);
}

int syz_invoke_driver(int cmd, unsigned long arg, unsigned size)
{
	switch (cmd) {
	case 1:
		return init_driver();
	case 2:
		return enable_driver();
	case 3:
		return disable_driver();
	case 4:
		return close_driver();
	case 5:
		return analyze_driver(arg);
	default:
		test_driver();
		break;
	}
    return 1;
}

int64_t syz_convert_to_int(unsigned long arg, int32_t size)
{
	if (arg == 0) {
		return -1;
	}
	switch (size) {
	case 1:
		return *(int8_t*)arg;
	case 2:
		return *(int16_t*)arg;
	case 3:
	case 4:
		return *(int32_t*)arg;
	case 5:
	case 6:
	case 7:
	case 8:
		return *(int64_t*)arg;
	default:
		printf("unacceptable arg to convert\n");
		break;
	}
	return -1;
}

#endif
