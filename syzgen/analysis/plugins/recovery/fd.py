
from syzgen.analysis.plugins.recovery import BaseAnnotation
from syzgen.target import TargetOS


class GetUnusedFD(BaseAnnotation):
    """get_unused_fd_flags(flags)"""
    TARGETS = [TargetOS.LINUX, TargetOS.ANDROID]
    ARGS = [(0, False, "flags[open_flags]", 4)]
    FUNCTION = "get_unused_fd_flags"
