
from typing import List, Union
from syzgen.kext.macho import Method, Service, UserClient
from syzgen.parser.models import Address, BaseModel, SyscallModel
from syzgen.parser.syscalls import Syscall
from syzgen.parser.syscalls.iokit import IOConnectCallAsyncMethod, IOConnectCallMethod, ServiceOpen
from syzgen.parser.types import Buffer, BufferOffset, ConstType, Constant, NullPointer, Pointer, PtrDir, ResourceType, StructType, int2bytes


def _init_IOConnectCallMethod_with_method(
    model: SyscallModel,
    syscall: Union[IOConnectCallMethod, IOConnectCallAsyncMethod],
    method: Method,
    cmd: int,
) -> None:
    port = ResourceType(
        {"name": "%s_port" % model.name,
            "parent": "io_connect_t", "data": int2bytes(0, 8)},
        typename="connection"
    )
    syscall.connection = port
    if method is None:
        return

    scalarInputCnt = method.getScalarInputCount()
    if scalarInputCnt not in (-1, 0xffffffff):
        syscall.inputCnt = Constant(
            scalarInputCnt, 4, IOConnectCallMethod.ARG_INPUT_CNT)
        if scalarInputCnt:
            fields = []
            for i in range(scalarInputCnt):
                fields.append(BufferOffset(8, i*8, None).toJson())
            if len(fields) == 1:
                syscall.input = Pointer(
                    fields[0], IOConnectCallMethod.ARG_INPUT)
            else:
                syscall.input = Pointer(
                    StructType({"fields": fields}, offset=0).toJson(),
                    IOConnectCallMethod.ARG_INPUT,
                )
        else:
            syscall.input = NullPointer(0, IOConnectCallMethod.ARG_INPUT)

    structInputSize = method.getStructInputSize()
    if structInputSize not in (-1, 0xffffffff):
        syscall.inputStructCnt = Constant(
            structInputSize, 4, IOConnectCallMethod.ARG_INPUTSTRUCT_CNT)
        if structInputSize:
            syscall.inputStruct = Pointer(
                Buffer(structInputSize, None).toJson(), IOConnectCallMethod.ARG_INPUTSTRUCT)
        else:
            syscall.inputStruct = NullPointer(
                0, IOConnectCallMethod.ARG_INPUTSTRUCT)

    scalarOutputCnt = method.getScalarOutputCount()
    if scalarOutputCnt not in (-1, 0xffffffff):
        if scalarOutputCnt:
            syscall.outputCnt = Pointer(
                Constant(scalarOutputCnt, 4, None).toJson(),
                IOConnectCallMethod.ARG_OUTPUT_CNT,
            )
            fields = []
            for i in range(scalarOutputCnt):
                fields.append(BufferOffset(8, i*8, None).toJson())
            if len(fields) == 1:
                syscall.output = Pointer(
                    fields[0], IOConnectCallMethod.ARG_OUTPUT)
            else:
                syscall.output = Pointer(StructType(
                    {"fields": fields}).toJson(), IOConnectCallMethod.ARG_OUTPUT)
            syscall.output.dir = PtrDir.DirOut
        else:
            syscall.outputCnt = NullPointer(
                0, IOConnectCallMethod.ARG_OUTPUT_CNT)
            syscall.output = NullPointer(0, IOConnectCallMethod.ARG_OUTPUT)
    structOutputSize = method.getStructOutputSize()
    if structOutputSize not in (-1, 0xffffffff):
        if structOutputSize:
            syscall.outputStructCnt = Pointer(
                Constant(structOutputSize, 4, None).toJson(),
                IOConnectCallMethod.ARG_OUTPUTSTRUCT_CNT,
            )
            syscall.outputStruct = Pointer(
                Buffer(structOutputSize, None).toJson(),
                IOConnectCallMethod.ARG_OUTPUTSTRUCT,
            )
            syscall.outputStruct.dir = PtrDir.DirOut
        else:
            syscall.outputStructCnt = NullPointer(
                0, IOConnectCallMethod.ARG_OUTPUTSTRUCT_CNT)
            syscall.outputStruct = NullPointer(
                0, IOConnectCallMethod.ARG_OUTPUTSTRUCT)

    syscall.validate()
    syscall.getCmdHandler(model.dispatcher.selector, cmd=cmd)
    if syscall.selector.type != "const":
        # FIXME: default selector is 0
        syscall.selector = ConstType(
            {"data": int2bytes(0, 4)}, typename="selector")


class IOConnectCallMethodModel(SyscallModel[IOConnectCallMethod, Method]):
    def init_syscall(self, cmd: int, method: Method) -> IOConnectCallMethod:
        subname = Syscall.SUBNAME_FORMAT.format(self.name, cmd, 0)
        syscall = IOConnectCallMethod(subname)
        _init_IOConnectCallMethod_with_method(self, syscall, method, cmd)
        return syscall


class IOConnectCallAsyncMethodModel(SyscallModel[IOConnectCallAsyncMethod, Method]):
    def init_syscall(self, cmd: int, method: Method) -> IOConnectCallAsyncMethod:
        subname = Syscall.SUBNAME_FORMAT.format(self.name, cmd, 0)
        syscall = IOConnectCallAsyncMethod(subname)
        _init_IOConnectCallMethod_with_method(self, syscall, method, cmd)
        return syscall


class IOKitModel(BaseModel):
    """Model for IOKit consisting of IOConnectCallMethod and IOConnectCallAsyncMethod"""

    def initialize(self, service: Service = None, client: UserClient = None) -> None:
        if service is None or client is None:
            raise RuntimeError("empty service or client")

        self.add_syscall(ServiceOpen.create(service.metaClass, client.type, client.metaClass))
        if client.externalMethod or client.getTargetAndMethodForIndex:
            self.add_syscall(IOConnectCallMethodModel(
                client.metaClass,
                Address(client.module, client.externalMethod or client.getTargetAndMethodForIndex))
            )

        # TODO: async
        # if self.IOConnectCallAsyncMethod:
        #     self.IOConnectCallAsyncMethod.initialize()
        super().initialize()

    def get_extra_syscalls(self) -> List[str]:
        ret = super().get_extra_syscalls()
        ret.append("syz_IOServiceClose")
        return ret
