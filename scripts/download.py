
import argparse
import logging
import multiprocessing
import os
import subprocess

logger = logging.getLogger("syzgen")


def tweak_config(filepath, enables, disables):
    with open(filepath, "r") as fp:
        cont = fp.read()
        for each in enables:
            cont = cont.replace(f"# {each} is not set", f"{each}=y")
        for each in disables:
            cont = cont.replace(f"{each}=y", f"# {each} is not set")
    with open(filepath, "w") as fp:
        fp.write(cont)


def get_def_config(source_dir, fuzzing=False):
    subprocess.run(["make", "defconfig"], cwd=source_dir, check=True)
    subprocess.run(["make", "kvm_guest.config"], cwd=source_dir, check=True)

    # tweak config
    enables = [
        "CONFIG_NAMESPACES",
        "CONFIG_DEBUG_INFO",
        "CONFIG_CONFIGFS_FS",
        "CONFIG_SECURITYFS",
        # for kprobes and ftrace
        "CONFIG_FUNCTION_TRACER",
        # additonal module to test
        # ppp also has suboptions
        "CONFIG_PPP",
    ]

    if fuzzing:
        enables.append("CONFIG_KCOV")
        enables.append("CONFIG_KASAN")
        # It is a suboption and not sure we need to enable it
        # "CONFIG_KASAN_INLINE"

    disables = [
        "CONFIG_RANDOMIZE_BASE",
    ]
    tweak_config(os.path.join(source_dir, ".config"), enables, disables)
    subprocess.run(["make", "olddefconfig"], cwd=source_dir, check=True)


def get_config_from_url(source_dir, url, fuzzing=False):
    config = os.path.join(source_dir, ".config")
    with open(config, "w") as fp:
        subprocess.run(["curl", url], stdout=fp, check=True)

    # tweak config
    enables = [
        # for kprobes and ftrace
        "CONFIG_FUNCTION_TRACER",
        "CONFIG_KPROBES",
        # Loadable modules
        # "CONFIG_MODULE_COMPRESS_NONE",
    ]
    disables = [
        # KASLR
        "CONFIG_RANDOMIZE_BASE",
        # MODULE signature
        "CONFIG_MODULE_FORCE_LOAD",
        "CONFIG_MODVERSIONS",
        "CONFIG_ASM_MODVERSIONS",
        "CONFIG_MODULE_SRCVERSION_ALL",
        "CONFIG_MODULE_SIG",
        "CONFIG_SECURITY_LOCKDOWN_LSM",
    ]
    if not fuzzing:
        disables.extend([
            # KCOV
            "CONFIG_KCOV",
            "CONFIG_KCOV_ENABLE_COMPARISONS",
            "CONFIG_KCOV_INSTRUMENT_ALL",
            # KASAN
            "CONFIG_KASAN",
            "CONFIG_KASAN_EXTRA",
            "CONFIG_KASAN_INLINE",
            "CONFIG_KASAN_OUTLINE",
            # UBSAN
            "CONFIG_UBSAN",
            "CONFIG_UBSAN_SANITIZE_ALL",

            # debugging features
            "CONFIG_PROVE_LOCKING",
            "CONFIG_DEBUG_ATOMIC_SLEEP",
            "CONFIG_DEBUG_PER_CPU_MAPS",
            "CONFIG_DEBUG_TIMEKEEPING",
            "CONFIG_DEBUG_RT_MUTEXES",
            "CONFIG_DEBUG_SPINLOCK",
            "CONFIG_DEBUG_MUTEXES",
            "CONFIG_DEBUG_WW_MUTEX_SLOWPATH",
            "CONFIG_DEBUG_RWSEMS",
            "CONFIG_DEBUG_LOCK_ALLOC",
            "CONFIG_LOCKDEP",
            "CONFIG_TRACE_IRQFLAGS",
            "CONFIG_TRACE_IRQFLAGS_NMI",
            "CONFIG_PROVE_RCU",
            "CONFIG_PREEMPTIRQ_TRACEPOINTS",

            "CONFIG_NET_SCHED",
        ])

    tweak_config(config, enables, disables)
    subprocess.run(["make", "olddefconfig"], cwd=source_dir, check=True)


def download_linux(out_dir, version, build=False, config_url=""):
    try:
        os.mkdir(out_dir)
    except:
        pass

    url = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
        f"linux.git/snapshot/linux-{version}.tar.gz"
    )
    outfile = os.path.join(out_dir, f"linux-{version}.tar.gz")
    # Download the kernel
    if not os.path.exists(outfile):
        cmds = [
            "wget",
            url,
            "-O",
            outfile,
        ]
        subprocess.run(cmds, check=True)
    # Untar the file
    kernelForFuzzing = os.path.join(out_dir, f"linux-{version}-fuzz")
    rawKernel = os.path.join(out_dir, f"linux-{version}-raw")
    for out in [kernelForFuzzing, rawKernel]:
        if not os.path.exists(out):
            os.mkdir(out)
            cmds = [
                "tar",
                "-xf",
                outfile,
                "-C", out,
                "--strip-components=1",
            ]
            subprocess.run(cmds, check=True)

        if config_url:
            get_config_from_url(out, config_url, out == kernelForFuzzing)
        else:
            get_def_config(out, out == kernelForFuzzing)
        if build:
            cpu_cores = multiprocessing.cpu_count()
            print("having %s cpu cores" % cpu_cores)
            subprocess.run(["make", f"-j{min(32, cpu_cores)}"], cwd=out, check=True)


def clean(out_dir, version):
    kernelForFuzzing = os.path.join(out_dir, f"linux-{version}-fuzz")
    rawKernel = os.path.join(out_dir, f"linux-{version}-raw")
    for out in [kernelForFuzzing, rawKernel]:
        if os.path.exists(out):
            subprocess.run(["make", "clean"], cwd=out, check=True)

# python scripts/download.py -c "https://syzkaller.appspot.com/text?tag=KernelConfig&x=dd7c9a79dfcfa205" --build -v 5.15


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="main")
    parser.add_argument("-v", "--version", required=True,
                        help="kernel version")
    parser.add_argument("-o", "--out", default="linux-distro",
                        help="output dir to store kernel source code (default: ./linux-distro)")
    parser.add_argument("-c", "--config", default="", help="url to .config")
    parser.add_argument("--build", action="store_true",
                        default=False, help="build kernel")
    parser.add_argument("--clean", action="store_true",
                        default=False, help="clean kernel binary")

    args = parser.parse_args()
    if args.clean:
        clean(args.out, args.version)
    else:
        download_linux(args.out, args.version, args.build, args.config)
