
#ifndef SYZGEN_DRIVER_HEADER_H
#define SYZGEN_DRIVER_HEADER_H
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define PREFIX "syzgen:"
#define HOOK_FD         _IO('c', 112)

typedef struct fd_operations {
    unsigned long fd;
    unsigned long read;
    unsigned long write;
    unsigned long unlocked_ioctl;
    unsigned long compat_ioctl;
    unsigned long open;
} fd_operations_t;

int syzgen_print(unsigned long arg, unsigned size) {
    switch (size) {
    case 1:
        printf(PREFIX " res %d\n", *(int8_t*)arg);
        break;
    case 2:
        printf(PREFIX " res %d\n", *(int16_t*)arg);
        break;
    case 8:
        printf(PREFIX " res %ld\n", *(int64_t*)arg);
        break;
    case 4:
    default:
        printf(PREFIX " res %d\n", *(int32_t*)arg);
        break;
    }
    return 0;
}

int syzgen_check_resource(signed long arg, unsigned size) {
    if (size > 0) {
        // It is a pointer
        syzgen_print(arg, size);
    } else {
        printf(PREFIX " res %ld\n", arg);
    }
    return 0;
}

int syzgen_check_fd(int fd) {
    fd_operations_t ops = { .fd = fd };
    int driver_fd = open("/sys/kernel/debug/hook", O_RDWR);
    if (driver_fd == -1) {
        perror("open");
        return 1;
    }

    if (driver_fd == -1) {
        printf("driver_fd: %d\n", driver_fd);
        return 1;
    }
    if (ioctl(driver_fd, HOOK_FD, &ops)) {
        perror("ioctl fd");
        return 1;
    }
    printf("read: 0x%lx\n", ops.read);
    printf("write: 0x%lx\n", ops.write);
    printf("unlocked_ioctl: 0x%lx\n", ops.unlocked_ioctl);
    printf("compat_ioctl: 0x%lx\n", ops.compat_ioctl);
    printf("open: 0x%lx\n", ops.open);
    return 0;
}

int syz_invoke_driver(int cmd, unsigned long arg, unsigned size) {
    switch (cmd)
    {
    case 0:
        return syzgen_print(arg, size);
    case 1:
        return syzgen_check_resource(arg, size);
    case 2:
        return syzgen_check_fd(arg);
    default:
        break;
    }
    return 0;
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