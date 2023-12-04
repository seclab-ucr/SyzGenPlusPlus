
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "hook.h"

int get_fd_operations(int driver_fd, unsigned long fd) {
    fd_operations_t ops = { .fd = fd };
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

int main(int argc, char **argv) {
    char* dev = argv[1];
    int fd, driver_fd;

    if (argc <= 1) {
        printf("Usage: getfd /dev/name");
        return 1;
    }
    printf("driver name: %s\n", dev);

    fd = open(dev, O_WRONLY);
    if (fd == -1) {
        perror("open dev");
        return 1;
    }
    driver_fd = open("/sys/kernel/debug/hook", O_RDWR);
    if (driver_fd == -1) {
        perror("open");
        return 1;
    }
    get_fd_operations(driver_fd, fd);
    close(driver_fd);
    close(fd);
    return 0;
}