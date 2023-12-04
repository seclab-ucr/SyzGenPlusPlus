obj-m += hook.o
hook-objs := src/hook_kprobe.o src/interface.o
EXTRA_CFLAGS := -I$(src)/lib

# all:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
# clean:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
all:
	make -C $(KERNEL) M=$(PWD) modules > /dev/null
clean:
	make -C $(KERNEL) M=$(PWD) clean
