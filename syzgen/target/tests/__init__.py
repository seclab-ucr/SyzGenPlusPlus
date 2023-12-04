
import logging
import unittest

from syzgen.target import Target


logging.basicConfig()
logger = logging.getLogger("syzgen")


class TestTarget(unittest.TestCase):
    def setUp(self) -> None:
        self.target = Target.Create()

        super().setUp()
