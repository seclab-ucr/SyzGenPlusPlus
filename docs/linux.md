# Tutorial on Linux

## Setup
See more [details](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md) on how to run syzkaller against Linux on a Linux machine.

```
# download linux source code
# we need two versions: one for fuzzing with kcov/kasan and the other raw version for analysis.
# if you need to tweek the config, do not enable --build and build them later manually.
mkdir linux-distro
python scripts/download.py -o linux-distro -v version/of/linux/to/test --build
# if you already have a config (e.g., from syzbot), you can just provide the link to it as follows:
python scripts/download.py -c "https://syzkaller.appspot.com/text?tag=KernelConfig&x=dd7c9a79dfcfa205" --build -v 5.15

# Create a Debian Stretch Linux image
sudo apt install debootstrap
mkdir linux-distro/image
cd linux-distro/image
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh
./create-image.sh

# install qemu
sudo apt install qemu-system-x86
qemu-system-x86_64 \
	-m 2G \
	-smp 2 \
	-kernel ${PWD}/../linux-5.15-fuzz/arch/x86/boot/bzImage \
	-append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
	-drive file=${PWD}/stretch.img,format=raw \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-enable-kvm \
	-nographic \
	-pidfile vm.pid \
	2>&1 | tee vm.log

```

### Generate basic config
```
python scripts/genConfig.py --name 5.15 -t linux --type qemu --image linux-distro/image --version 5.15
```

You can find the config file at the current dir and its name by default is `config` (see [config](config.md) for more details).

## Running

First, run the following command to scan the /dev folder inside a VM to get all loaded drivers and their points:

```
python main.py --find_drivers
```

The results would be kept in a json file at the path `workdir/Your-Project-Name/model/services.json` which contains all relevant information about drivers.

Second, now we can analyze one particular driver on demand. Each driver is assigned a unique name based on its path and you can find it in the services.json file (i.e., the name field).

For driver interface like `ioctl`, there is typically a command idendifier (e.g., the second argument of ioctl). Because we would like to analyze each command separately, the next step is to extract all valid command values as follows:

```
python main.py --target name-of-the-driver --find_cmds --dynamic (optional)
```

in which, `--dynamic` specifies that it performs in-vivo symbolic execution that incorporates runtime information (i.e., read concrete kernel memory from a VM instead of symbolizing it).

To check all the command values it extracts, we provide the following command:

```
python main.py --target name-of-the-driver --show
```

Last, run the following command to generate the specifications:

```
python main.py --target name-of-the-driver --infer_type --dynamic (optional)
```

All specifications are put uder the folder `gopath/src/github.com/google/syzkaller/sys/linux (or darwin)/`.
