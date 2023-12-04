
import logging
import os
import subprocess
import time
from typing import Any, Dict, List
from syzgen.config import Options
from syzgen.utils import UnusedTcpPort

from syzgen.vm import VMInstance

logger = logging.getLogger(__name__)
options = Options()


class QEMUInstance(VMInstance):
    """Start a QEMU instance
    qemu-system-x86_64 \
        -m 2G \
        -smp 2 \
        -kernel /home/wchen130/workplace/SyzGen_setup/linux-5.15/arch/x86/boot/bzImage \
        -append "console=ttyS0 root=/dev/sda net.ifnames=0" \
        -hda /home/wchen130/workplace/SyzGen_setup/debian/stretch.img \
        -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=51727 \
        -mon chardev=SOCKSYZ,mode=control \
        -device virtio-rng-pci \
        -device e1000,netdev=net0 \
        -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:10021-:22 \
        -enable-kvm \
        -display none \
        -pidfile vm.pid \
        -serial stdio \
        -cpu host,migratable=off \
        -no-reboot -name VM-0 -snapshot \
        2>&1 | tee vm.log
    """

    def __init__(
        self,
        kernel_dir: str,
        image: str,
        key: str,
        user: str="root",
        ip: str="localhost",
        ssh_port: int=0,
        gdb_port: int=0,
        memory: str="2G",
        cpu: int=2,
        enable_kvm: bool=True,
        name="VM"
    ) -> None:
        super().__init__(kernel_dir, user=user)

        self._kernel = os.path.join(
            kernel_dir, "arch", "x86", "boot", "bzImage")
        self._image = image
        self._key = key
        self._ip = ip
        self._ssh_port = ssh_port
        self._gdb_port = 1234 if options.debug_vm else gdb_port
        self._memory = memory
        self._cpu = cpu
        self._enable_kvm = enable_kvm
        self._name = name

    def copy(self) -> "QEMUInstance":
        return QEMUInstance(
            self.kernel_dir,
            self._image,
            self._key,
            user=self.user,
            ip=self._ip,
            ssh_port=0,
            gdb_port=0,
            memory=self._memory,
            cpu=self._cpu,
            enable_kvm=self._enable_kvm,
            name=self._name,
        )

    def run(self):
        self._ssh_port = self._ssh_port or UnusedTcpPort()
        self._gdb_port = self._gdb_port or UnusedTcpPort()
        cmds = [
            "qemu-system-x86_64",
            "-m", self._memory,
            "-smp", str(self._cpu),
            "-kernel", self._kernel,
            "-append", "console=ttyS0 root=/dev/sda net.ifnames=0",
            "-hda", self._image,
            "-chardev",
            f"socket,id=SOCKSYZ,server=on,nowait,host=localhost,port={UnusedTcpPort()}",
            "-mon", "chardev=SOCKSYZ,mode=control",
            "-device", "virtio-rng-pci",
            "-device", "e1000,netdev=net0",
            "-netdev", f"user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{self._ssh_port}-:22",
            "-display", "none",
            "-serial", "stdio",
            "-cpu", "host,migratable=off",
            "-no-reboot",
            "-name", self._name,
            "-snapshot",
            "-gdb", f"tcp::{self._gdb_port}",
        ]
        if self._enable_kvm:
            cmds.append("-enable-kvm")

        logger.debug("start the vm: %s", " ".join(cmds))
        self._process = subprocess.Popen(cmds, stdout=None if options.debug else subprocess.DEVNULL)
        self._process.communicate()

    def get_type(self) -> str:
        return "qemu"

    def get_ssh_cmd(self) -> List[str]:
        return [
            "ssh",
            "-i", self._key,
            "-p", str(self._ssh_port),
            "-o", "StrictHostKeyChecking no",
            f"{self.user}@{self._ip}"
        ]

    def get_scp_cmd(self, src, dst) -> List[str]:
        return [
            "scp",
            "-i", self._key,
            "-P", str(self._ssh_port),
            "-o", "StrictHostKeyChecking no",
            src,
            f"{self.user}@{self._ip}:{dst}"
        ]

    def wait_for_ssh(self, timeout=120):
        time.sleep(5)
        return super().wait_for_ssh(timeout=timeout)

    def suspend(self):
        pass

    def get_ip(self) -> str:
        return self._ip

    def get_debug_port(self) -> int:
        return self._gdb_port

    def get_ssh_port(self) -> int:
        return self._ssh_port

    def get_kernel(self) -> str:
        return os.path.join(self.kernel_dir, "vmlinux")

    @staticmethod
    def initialize(**kwargs):
        return QEMUInstance(
            # kernel_dir
            kwargs.pop("kernel", "") or options.getConfigKey("kernel"),
            kwargs.pop("image", "") or options.getConfigKey("image"),
            kwargs.pop("sshkey", "") or options.getConfigKey("sshkey"),
        )

    def genSyzConfig(self, num_cpu=2, num_vm=1, **kwargs) -> Dict[str, Any]:
        return {
            "sshkey": options.getConfigKey("sshkey"),
            "ssh_user": self.user,
            "kernel_obj": options.getConfigKey("kernel"),
            "image": options.getConfigKey("image"),
            "vm": {
                "count": num_vm,
                "cpu": num_cpu,
                "mem": 2048,
                "cmdline": "net.ifnames=0",
                "kernel": os.path.join(options.getConfigKey("kernel"), "arch", "x86", "boot", "bzImage"),
            }
        }


def TestQEMUInstance():
    inst = QEMUInstance(
        options.getConfigKey("kernel"),
        options.getConfigKey("image"),
        options.getConfigKey("sshkey"),
    )
    with inst:
        # inst.start()
        inst.wait_for_ssh()
        inst.copy_file("invalid_prog.syz", "/invalid_prog.syz")
        inst.copy_file("valid_prog.syz", "/valid_prog.syz")
        # inst.copy_file("test.syz", "/test.syz")
        inst.copy_file(
            os.path.join(options.getConfigKey("syzkaller"),
                         "bin", "linux_amd64", "syz-run"),
            "/syz-run"
        )
        inst.copy_file(
            os.path.join(options.getConfigKey("syzkaller"),
                         "bin", "linux_amd64", "syz-executor"),
            "/syz-executor"
        )
        ret = inst.run_cmd([
            "/syz-run",
            "-executor=/syz-executor",
            "-vv=100",
            "-cover",
            "-collide=false",
            "-threaded=false",
            "-output=true",
            # "-debug",
            # "-coverfile=1",
            "-syscall=ioctl\\$ppp_Group4004743d_0",
            "/invalid_prog.syz",
            "/valid_prog.syz",
        ], enable_stderr=True)
        if b"sys-run: Succeed!" in ret.stderr:
            logger.debug("Succeed!!!")
        else:
            logger.debug("Failed!!!")
