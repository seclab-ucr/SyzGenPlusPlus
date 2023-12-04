
from typing import List
from syzgen.analysis.plugins.recovery import ArgAnnotation, BaseAnnotation
from syzgen.target import TargetOS


class withCString(BaseAnnotation):
    """static OSString * withCString(const char *cString);"""

    TARGETS = [TargetOS.DARWIN]
    ARGS: List[ArgAnnotation] = [(0, True, "string", 0)]
    FUNCTION = "OSString::withCString"
