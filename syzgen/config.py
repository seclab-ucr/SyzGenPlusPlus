
from argparse import ArgumentParser
from enum import Enum

import json
import os
from typing import Optional

WORKDIR = "workdir"
CONFIG_PATH = "config"

if not os.path.exists(WORKDIR):
    os.mkdir(WORKDIR)

DEBUG = False
def str2bool(x): return x not in {"False", "false"}

class AnalysisType(Enum):
    ALL         = 0
    FIND_CMD    = 1
    FIND_DRIVER = 2
    INFER_TYPE  = 3

    # Utility
    SHOW         = 10
    GEN_TEMPLATE = 11
    GEN_MODEL    = 12

    def require_target(self) -> bool:
        return self in [
            AnalysisType.ALL,
            AnalysisType.FIND_CMD,
            AnalysisType.INFER_TYPE,
            AnalysisType.GEN_TEMPLATE,
            AnalysisType.GEN_MODEL,
            AnalysisType.SHOW,
        ]

def str2typenum(x): return AnalysisType[x.upper()]

plugin_options = {
    "plugin": [
        {
            "name": "debug",
            "args": {
                "default": False,
                "action": "store_true",
                "help": "print debug info to file output.log",
            }
        },
        {
            "name": "timeout",
            "args": {
                "default": 10*60,
                "type": int,
                "help": "set timeout (s)"
            }
        },
        {
            "name": "ignore_error",
            "args": {
                "default": True,
                "type": str2bool,
                "help": "ignore error states"
            }
        },
        {
            "name": "hook_point",
            "args": {
                "choices": ["post", "pre", "access"],
                "help": "add breakpoint for debugging"
            }
        },
        {
            "name": "dynamic",
            "args": {
                "default": False,
                "action": "store_true",
                "help": "static or dynamic mode"
            }
        },
        {
            "name": "debug_vm",
            "args": {
                "default": False,
                "action": "store_true",
                "help": "debug vm"
            }
        },
        {
            "name": "syscall_suffix",
            "args": {
                "default": "",
                "help": "syscall suffix"
            }
        },
        {
            "name": "process_once",
            "args": {
                "default": False,
                "action": "store_true",
                "help": "only process one syscall and then quit (for debugging purpose)"
            }
        }
    ],
    "VisitedFunctionsPlugin": [
        {
            "name": "print_function",
            "args": {
                "default": False,
                "action": "store_true",
                "help": "show lines of functions we executed"
            }
        },
    ],
    "RecordAccessPathPlugin": [
        {
            "name": "infer_dependence",
            "args": {
                "default": True,
                "type": str2bool
            }
        }
    ],
    "InputRecoveryPlugin": [
        {
            "name": "zero_unused",   # reduce the input space if we do not have coverage feedback
            "args": {
                "default": False,
                "type": str2bool,
                "help": "make unused fields zero"
            }
        },
        {
            "name": "max_syscalls",
            "args": {
                "default": 64,
                "type": int,
                "help": "maximum number of paths for one interface"
            }
        },
        {
            "name": "max_specs",
            "args": {
                "default": 16,
                "type": int,
                "help": "maximum number of specs for one interface"
            }
        },
        {
            "name": "max_diff",
            "args": {
                "default": 8,
                "type": int,
                "help": "merge two templates if they have at most Y differences (conservatively)"
            }
        },
        {
            "name": "min_diff",
            "args": {
                "default": 1,
                "type": int,
                "help": "merge two templates if they have at most X differences (aggressively)"
            }
        },
        {
            "name": "non_empty",
            "args": {
                "default": True,
                "type": str2bool,
                "help": "each cmd has at least one spec"
            }
        }
    ],
    "ForkProfilePlugin": [
        {
            "name": "fork_profile",
            "args": {
                "default": False,
                "action": "store_true",
                "help": "fork profile"
            }
        }
    ],
    "VisitedBlocksPlugin": [
        {
            "name": "cover",
            "args": {
                "default": False,
                "action": "store_true",
                "help": "generate coverage report"
            }
        }
    ],
    "SymbolizationPlugin": [
        {
            "name": "no_symbolization",
            "args": {
                "default": False,
                "action": "store_true",
                "help": "disable SymbolizationPlugin"
            }
        }
    ],
}


class MissingKeyInConfigError(Exception):
    pass


class Options:
    _instance = None

    def __init__(self):
        if getattr(self, "debug", None) is not None:
            return

        self.debug = False

        # internal
        self.struct_recovery = True
        self.config = None

        self.heap_allocator = None
        self.record_access_path = False

        self.step: Optional[AnalysisType] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Options, cls).__new__(cls)
        return cls._instance

    def add_options(self, parser: ArgumentParser):
        for _, items in plugin_options.items():
            for each in items:
                name = each["name"]
                args = each["args"]
                parser.add_argument(f"--{name}", **args)

    def set_options(self, args):
        if args and getattr(args, "step", None):
            self.step = args.step

        for plugin, items in plugin_options.items():
            for each in items:
                name = each["name"]
                val = None
                if args is None:
                    if "args" in each and "default" in each["args"]:
                        val = each["args"]["default"]
                else:
                    val = getattr(args, name)
                setattr(self, name, val)
                print(f"{plugin} {name}: {val}")

        # Debug mode, check all errors
        if self.debug:
            self.ignore_error = False

    def loadConfig(self):
        if self.config is None:
            with open(CONFIG_PATH, "r") as fp:
                self.config = json.load(fp)

    def saveConfig(self):
        if self.config is not None:
            with open(CONFIG_PATH, "w") as fp:
                json.dump(self.config, fp, indent=2)

    def getConfigKey(self, key: str, default=None):
        self.loadConfig()

        if key not in self.config:
            if default is None:
                raise MissingKeyInConfigError(
                    f"Can not find key \"{key}\" in the config file")
            return default
        return self.config[key]

    def setConfigKey(self, key, value):
        self.loadConfig()
        self.config[key] = value
        self.saveConfig()
