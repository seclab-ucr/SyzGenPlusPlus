
from syzgen.analysis.plugins.recovery import BaseAnnotation
from syzgen.target import TargetOS


class AnnotateIPv4Addr(BaseAnnotation):
    """struct net_device *__ip_dev_find(struct net *net, __be32 addr, bool devref)
    https://elixir.bootlin.com/linux/v5.15/source/net/ipv4/devinet.c#L150"""

    TARGETS = [TargetOS.LINUX, TargetOS.ANDROID]
    ARGS = [(1, False, "ipv4_addr", 4)]
    FUNCTION = "__ip_dev_find"
