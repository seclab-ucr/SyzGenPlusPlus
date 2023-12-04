
from syzgen.models import DummyModel
from syzgen.models.linux import LinuxModel


class AndroidModel(LinuxModel):
    def getFunc2Model(self):
        retWithZero = DummyModel("retWithZero")
        procedures = {
            "__cfi_check": retWithZero,
            "__clk_recalc_rates": retWithZero,
        }
        procedures.update(super().getFunc2Model())
        return procedures
