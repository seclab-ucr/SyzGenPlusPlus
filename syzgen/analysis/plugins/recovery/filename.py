
from typing import List
from syzgen.analysis.plugins.recovery import ArgAnnotation, BaseAnnotation
from syzgen.target import TargetOS


class KernPathAnnotation(BaseAnnotation):
    """int kern_path(const char *name, unsigned int flags, struct path *path)"""

    TARGETS = [TargetOS.LINUX, TargetOS.ANDROID]
    ARGS: List[ArgAnnotation] = [(0, True, "filename", 0)]
    FUNCTION = "kern_path"


class GetnameKernel(BaseAnnotation):
    """struct filename *getname_kernel(const char * filename)"""

    TARGETS = [TargetOS.LINUX, TargetOS.ANDROID]
    ARGS: List[ArgAnnotation] = [(0, True, "filename", 0)]
    FUNCTION = "getname_kernel"
