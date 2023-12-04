
import logging

from syzgen.analysis.plugins.recovery import BaseAnnotation
from syzgen.target import TargetOS

logger = logging.getLogger(__name__)

class AnnotateSin6(BaseAnnotation):
    """int __ipv6_addr_type(const struct in6_addr *addr)
    see sys/linux/vnet.txt for type definition in syzkaller
    """

    TARGETS = [TargetOS.LINUX, TargetOS.ANDROID]
    ARGS = [(0, True, "ipv6_addr", 16)]
    FUNCTION = "__ipv6_addr_type"

class AnnotateIPv6ChkAddr(BaseAnnotation):
    """int ipv6_chk_addr(struct net *net, const struct in6_addr *addr,
		  const struct net_device *dev, int strict)
    net/ipv6/addrconf.c
    """

    TARGETS = [TargetOS.LINUX, TargetOS.ANDROID]
    ARGS = [(1, True, "ipv6_addr", 16)]
    FUNCTION = "ipv6_chk_addr"
