
from collections import defaultdict
import copy
import pickle
import logging
import os
from typing import Callable, Dict, Generator, Generic, List, NewType, Optional, Set, Tuple, TypeVar, Union

from claripy.ast.base import Base
from syzgen.analysis.access_path import AccessNode
from syzgen.parser.optimize import reduce_syscalls
from syzgen.parser.syscalls import Syscall, SyscallStatus, SyscallType


logger = logging.getLogger(__name__)

SyscallFilter = Callable[[Optional[int], Syscall], bool]
READ_ACCESS_PATHS = Dict[AccessNode, Tuple[List[int], int]]
WRITE_ACCESS_PATHS = Set[AccessNode]

BaseAddress = NewType("BaseAddress", int)
TargetAddress = NewType("TargetAddress", int)


class Address:
    def __init__(self, module: str, addr: BaseAddress) -> None:
        self.module: str = module
        self.address: BaseAddress = addr

    def __str__(self) -> str:
        return f"{self.module}({self.address:#x})"

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Address):
            return self.module == o.module and self.address == o.address
        return False


class MethodInfo:
    def __init__(self, module: str, addr: BaseAddress, cmd: int, name: Optional[str] = None) -> None:
        self.addr: Address = Address(module, addr)
        self.cmd: int = cmd
        self.method_name: Optional[str] = name

    def debug_repr(self) -> None:
        logger.info("%#x: %s", self.cmd, self.addr)

    def __str__(self) -> str:
        return f"{self.cmd:#x}: {self.addr}"


MethodInfoType = TypeVar("MethodInfoType", bound=MethodInfo)


class MethodTable(Generic[MethodInfoType]):
    def __init__(self, selector: Optional[Base] = None) -> None:
        # symbol to locate the selector: it can be either a separate argument or is embeded
        # in another argument. If the interface does not provide multiple functionalities,
        # the selector is None.
        self.selector: Optional[Base] = selector
        # cmd: functionality
        self.methods: Dict[int, MethodInfoType] = {}

    def addMethod(self, method: MethodInfoType) -> None:
        self.methods[method.cmd] = method

    def debug_repr(self) -> None:
        logger.info("Valid Command Values: %s", self.selector)
        for _, method in self.methods.items():
            method.debug_repr()

    def __len__(self):
        return len(self.methods)


class SimpleMethodTable(MethodTable[MethodInfo]):
    pass


class CommandExtractInterface:
    def get_method_table(self) -> Optional[MethodTable]:
        raise NotImplementedError()


class SyscallModel(Generic[SyscallType, MethodInfoType]):
    def __init__(self, name: str, entry: Address):
        self.name: str = name
        self.entry: Address = entry

        # methods = {"cmd": [sub_syscall1, ...]}
        # Each cmd may corresponds to multiple input structure and thus multiple syscall models.
        self.methods: Dict[int, List[SyscallType]] = {}
        self.dispatcher: Optional[MethodTable[MethodInfoType]] = None

        # cmd: patterns
        self.write_patterns: Dict[int, WRITE_ACCESS_PATHS] = defaultdict(set)
        # cmd: { pattern: (offset path, size)}
        self.read_patterns: Dict[int, READ_ACCESS_PATHS] = defaultdict(dict)

    def init_syscall(self, cmd: int, method: MethodInfoType) -> Syscall:
        raise NotImplementedError()

    def initialized(self) -> bool:
        return self.dispatcher is not None

    def initialize(self) -> None:
        self.methods.clear()
        if self.dispatcher is None or len(self.dispatcher.methods) == 0:
            self.methods[0] = [self.init_syscall(0, None)]
        else:
            for cmd, method in self.dispatcher.methods.items():
                self.methods[cmd] = [self.init_syscall(cmd, method)]

        # we may reset the model
        self.write_patterns.clear()
        self.read_patterns.clear()

    def syscalls(self, filter: Optional[SyscallFilter] = None) -> Generator[Syscall, None, None]:
        """Enumerate all syscalls
        filter: for each pair of (cmd, syscall), return false to skip it.
        By default we keep all syscalls"""
        for cmd in sorted(self.methods.keys()):
            for syscall in self.methods[cmd]:
                if filter is None or filter(cmd, syscall):
                    yield syscall

    def get_any_syscall(self) -> Optional[Syscall]:
        for syscall in self.syscalls():
            return syscall
        return None

    def get_syscalls(self, cmd: int) -> Generator[Syscall, None, None]:
        for syscall in self.methods[cmd]:
            yield syscall

    def copy(self) -> "SyscallModel":
        return copy.deepcopy(self)

    def reduce(self, cmd: int = -1):
        if cmd in self.methods:
            self.methods[cmd] = reduce_syscalls(self.methods[cmd])
            for i, each in enumerate(self.methods[cmd]):
                each.set_subname(self.name, cmd, i)
        else:
            for cmd in self.methods:
                self.methods[cmd] = reduce_syscalls(self.methods[cmd])
                for i, each in enumerate(self.methods[cmd]):
                    each.set_subname(self.name, cmd, i)

    def debug_repr(self, cmd: int = -1):
        logger.info("entry: %s(%#x)", self.entry.module, self.entry.address)
        if self.dispatcher:
            self.dispatcher.debug_repr()

        for syscall in self.syscalls(lambda c, _: cmd == -1 or cmd == c):
            logger.info(syscall.repr())

        for _cmd, patterns in self.write_patterns.items():
            if cmd != -1 and cmd != _cmd:
                continue
            if patterns:
                logger.info("write access path %#x: %d", _cmd, len(patterns))
                for each in patterns:
                    logger.info(each)

        for _cmd, patterns in self.read_patterns.items():
            if cmd != -1 and cmd != _cmd:
                continue
            if patterns:
                logger.info("read access path %#x: %d", _cmd, len(patterns))
                for p, (path, size) in patterns.items():
                    logger.info("%s: %s %d", p, path, size)


class BaseModel:
    """BaseMode for a module/driver consisting of Syscalls and/or SyscallModels"""

    def __init__(self, name: str) -> None:
        self.name: str = name

        # different models may have common cmds. To avoid conflicts, we need to
        # create a mapping from unique id to (model, cmd).
        self._cmd_mapping: List[Tuple[str, int]] = []

        self._all_syscalls: List[Union[Syscall, SyscallModel]] = []

    def add_syscall(self, syscall: Union[Syscall, SyscallModel]) -> Union[Syscall, SyscallModel]:
        assert syscall
        if isinstance(syscall, Syscall):
            for val in self._all_syscalls:
                if isinstance(val, Syscall):
                    if val.Name == syscall.Name:
                        return val
        elif isinstance(syscall, SyscallModel):
            for val in self._all_syscalls:
                if isinstance(val, SyscallModel):
                    if val.name == syscall.name and val.entry == syscall.entry:
                        return val

        self._all_syscalls.append(syscall)

        self.reset_mapping()

        return syscall

    def reset_mapping(self) -> None:
        self._cmd_mapping = []
        self._make_cmd_mapping()

    def get_extra_syscalls(self) -> List[str]:
        """Extra syscalls to enable for fuzzing"""
        ret = []
        for syscall in self.syscalls():
            for each in syscall.get_extra_syscalls():
                if each:
                    ret.append(each.Name)
        return ret

    def initialize(self, **kwargs) -> None:
        """Intialize all syscall models. Note we need to call this after we analyze
        certain syscalls (ie, find the dispatcher)."""
        for _, model in self._syscall_models():
            if not model.initialized():
                model.initialize()
                self.reset_mapping()

    def _syscalls(self) -> Generator[Optional[Syscall], None, None]:
        for val in self._all_syscalls:
            if isinstance(val, Syscall):
                yield val
            elif isinstance(val, SyscallModel):
                yield from val.syscalls()
            else:
                raise RuntimeError("invalid syscall %s" % type(val))

    def _syscall_models(self) -> Generator[Tuple[int, SyscallModel], None, None]:
        for num, val in enumerate(self._all_syscalls):
            if isinstance(val, SyscallModel):
                yield(num, val)

    def syscalls(self, filter: Optional[SyscallFilter] = None) -> Generator[Syscall, None, None]:
        """Enumerate all syscalls
        filter: for each pair of (cmd, syscall), return false to skip it.
        By default we keep all syscalls"""
        for each in self._syscalls():
            if each is None:
                continue
            if filter is None or filter(None, each):
                yield each

    def _make_cmd_mapping(self) -> None:
        if self._cmd_mapping:
            # FIXME: do we need to reset it after some changes?
            return
        for num, model in self._syscall_models():
            for cmd in model.methods:
                self._cmd_mapping.append((num, cmd))

    def get_read_access_paths(self) -> Generator[Tuple[int, READ_ACCESS_PATHS], None, None]:
        """return all read access paths and their fake cmd value"""
        self._make_cmd_mapping()
        for num, model in self._syscall_models():
            for cmd, reads in model.read_patterns.items():
                idx = self._cmd_mapping.index((num, cmd))
                yield idx, reads

    def get_write_access_paths(self) -> Generator[Tuple[int, WRITE_ACCESS_PATHS], None, None]:
        """return all write access paths and their fake cmd value"""
        self._make_cmd_mapping()
        for num, model in self._syscall_models():
            for cmd, writes in model.write_patterns.items():
                idx = self._cmd_mapping.index((num, cmd))
                yield idx, writes

    def get_syscall_model_by_name(self, name: str) -> SyscallModel:
        # format for name: syscallName$moduleName
        name, module = name.split("$")
        for _, val in self._syscall_models():
            if val.name == module and val.get_any_syscall().CallName == name:
                return val
        raise RuntimeError()

    def get_syscall_model(self, num: int) -> SyscallModel:
        """Return the i-th syscall model in the list"""
        ret = self._all_syscalls[num]
        assert isinstance(ret, SyscallModel)
        return ret

    def get_syscall(self, num: int) -> Syscall:
        """Return the i-th syscall in the list"""
        ret = self._all_syscalls[num]
        assert isinstance(ret, Syscall)
        return ret

    def set_syscall_model(self, num: int, model: SyscallModel) -> None:
        assert isinstance(model, SyscallModel)
        origin = self.get_syscall_model(num)
        if origin.name != model.name or origin.entry != model.entry:
            raise RuntimeError()
        self._all_syscalls[num] = model

    def remove_syscall(self, num: int) -> None:
        del self._all_syscalls[num]

    def methods(self, idx: int) -> Generator[Syscall, None, None]:
        """return all the methods corresponding to the given index"""
        num, cmd = self._cmd_mapping[idx]
        model: SyscallModel = self.get_syscall_model(num)
        for syscall in model.methods[cmd]:
            yield syscall

    def model(self, idx: int) -> Tuple[SyscallModel, int]:
        """return the model and cmd that correspond to the given index"""
        num, cmd = self._cmd_mapping[idx]
        model: SyscallModel = self.get_syscall_model(num)
        return model, cmd

    def reduce(self, idx: int) -> None:
        """reduce syscalls after we make any changes to them"""
        model, cmd = self.model(idx)
        model.reduce(cmd)

    def is_complete(self, idx: int) -> bool:
        for syscall in self.methods(idx):
            if syscall.status != SyscallStatus.FINISHED:
                return False
        return True

    def get_idx_repr(self, idx: int) -> str:
        """convert the index to its associated model and cmd"""
        num, cmd = self._cmd_mapping[idx]
        model = self.get_syscall_model(num)
        return f"{model.name}_{cmd:#x}"

    def debug_repr(self, cmd: int = -1):
        if cmd == -1:
            # show single syscalls
            for val in self._all_syscalls:
                if val and isinstance(val, Syscall):
                    logger.info(val.repr())

        for _, model in self._syscall_models():
            model.debug_repr(cmd=cmd)

    def copy(self) -> "BaseModel":
        return copy.deepcopy(self)

    @staticmethod
    def load(dir_path: str, module_name: str) -> Optional["BaseModel"]:
        p = os.path.join(dir_path, f"{module_name}.model")
        if not os.path.exists(p):
            return None

        with open(p, "rb") as fp:
            return pickle.load(fp)

    def save(self, dir_path: str) -> None:
        p = os.path.join(dir_path, f"{self.name}.model")
        with open(p, "wb") as fp:
            pickle.dump(self, fp)
