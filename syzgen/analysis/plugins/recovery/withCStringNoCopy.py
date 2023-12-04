
from typing import List
from syzgen.analysis.plugins.recovery import ArgAnnotation, BaseAnnotation
from syzgen.target import TargetOS


class withCStringNoCopy(BaseAnnotation):
    """static const OSSymbol * withCStringNoCopy(const char *cString);"""

    TARGETS = [TargetOS.DARWIN]
    ARGS: List[ArgAnnotation] = [(0, True, "string", 0)]
    FUNCTION = "OSSymbol::withCStringNoCopy"
