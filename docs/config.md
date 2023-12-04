
# Config
This file documents all the valid fields in a config file.

1. project_name: To distinguish different versions/tragets, we must provide a unique name and then all intermediate files pertaining to this particular project would be stored in an isolated folder.
2. target: the type of kernel we attempt to analyze, including android, linux, and macos.
3. type: the type of virtual machine we will use, including qemu, vmware, and adb.
4. user: user name to login the virtual machine.
5. kernel: the directory to the kernel code
6. binary: the directory to the kernel we attempt to analyze. Sometimes the kernel we analyze is different the kernel we load into the virtual machine, e.g., one with kcov and kasan, and the other one without those features.
7. syzkaller: path to the syzkaller's folder.
8. vmpath: for vmware, it requires the path to the vm we want to boot.
9. ip: the ip address of the vm. By default, it is localhost. For vmware, we can automatically detect the ip given vmpath.
10. driver_dir: for macos, we can provide the folder where we store all the driver bundles and syzgen would scan each file to find services.
