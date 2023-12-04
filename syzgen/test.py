
import json
import logging
import unittest

import syzgen.config as Config

from syzgen.config import Options
from syzgen.target import Target


logging.basicConfig()
logger = logging.getLogger("syzgen")
options = Options()

class BaseTestUnit(unittest.TestCase):
    def setUp(self, debug: bool = True, config: str = "config") -> None:
        Config.CONFIG_PATH = config
        options.set_options(None)
        options.debug = debug
        self.target = Target.Create()

        if debug and options.getConfigKey("debug", False):
            handler = logging.FileHandler("output.log", "w+")
            handler.setFormatter(logging.Formatter())
            logging.getLogger().addHandler(handler)
            logger.setLevel(logging.DEBUG)
        return super().setUp()

    def load_data(self, path: str):
        with open(path, "r") as fp:
            return json.load(fp)
