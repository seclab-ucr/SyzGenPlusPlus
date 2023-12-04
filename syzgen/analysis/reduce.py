
import logging
import heapq
import math
from typing import Any, List, Tuple

logger = logging.getLogger(__name__)

# Hierarchical agglomerative clustering


class Group:
    def __init__(self):
        self.points = []
        self.left = None
        self.right = None

    def getValue(self):
        return sum(v for _, v in self.points)/len(self.points)

    def display(self, depth=10):
        cur = [self]
        while depth and cur:
            logger.debug("%s", " ".join(
                map(str, [int(each.getValue()) for each in cur])))
            nxt = []
            for each in cur:
                if each.left:
                    nxt.append(each.left)
                if each.right:
                    nxt.append(each.right)
            cur = nxt
            depth -= 1


def clustering(points):
    groups: List[Group] = []
    for k, v in points:
        g = Group()
        g.points.append((k, v))
        groups.append(g)

    heap = []
    for i in range(len(groups)):
        for j in range(i+1, len(groups)):
            dist = abs(groups[i].getValue() - groups[j].getValue())
            heapq.heappush(heap, (dist, i, j))

    while heap:
        _, i, j = heapq.heappop(heap)
        if groups[i] and groups[j]:
            logger.debug("merging %d %d", i, j)
            g = Group()
            g.left = groups[i]
            g.right = groups[j]
            g.points.extend(groups[i].points)
            g.points.extend(groups[j].points)
            groups[i] = None
            groups[j] = None

            centric = g.getValue()
            for i, each in enumerate(groups):
                if each is not None:
                    dist = abs(each.getValue() - centric)
                    heapq.heappush(heap, (dist, i, len(groups)))
            groups.append(g)

    return groups[-1]


def getGroupAddrs(root):
    addrs = set()
    for state, _ in root.points:
        addrs.update(state.locals.get("visited", set()))
    return addrs


def canRemove(a, b, threshold):
    # whether we should remove A node
    if b.getValue()*threshold > a.getValue():  # and a.getValue() < 200:
        addr1 = getGroupAddrs(a)
        addr2 = getGroupAddrs(b)
        if addr1 - addr2:
            return False
        return True
    return False


def prune(root: Group, threshold):
    s1 = []
    s2 = []
    s1.append(root)

    while s1:
        cur = s1.pop()
        if cur.left and cur.right:
            if canRemove(cur.left, cur.right, threshold):
                cur.left = None
            elif canRemove(cur.right, cur.left, threshold):
                cur.right = None
        s2.append(cur)
        if cur.left:
            s1.append(cur.left)
        if cur.right:
            s1.append(cur.right)

    while s2:
        cur = s2.pop()
        if cur.left or cur.right:
            cur.points = []
            if cur.left:
                cur.points.extend(cur.left.points)
            if cur.right:
                cur.points.extend(cur.right.points)

    return root


def HAClustering(points: List[Tuple[Any, int]]):
    """Hierarchical agglomerative clustering"""
    if not points:
        return []
    threshold = min(math.log(len(points), 100), 1)/2 + 0.5
    logger.debug("%d points with threshold %f", len(points), threshold)
    logger.debug("%s", ", ".join(map(str, [x[1] for x in points])))
    root = clustering(points)
    root.display()
    # from IPython import embed; embed()
    root = prune(root, threshold)
    left = [point for point, _ in root.points]
    logger.debug("remaining points: %d", len(left))
    root.display()
    return left
