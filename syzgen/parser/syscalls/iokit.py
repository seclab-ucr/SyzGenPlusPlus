
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import BufferType, Constant, PtrDir, PtrType, RangeType, ResourceType, StringType, StructType, int2bytes


class ServiceOpen(Syscall):
    NAME = "syz_IOServiceOpen"
    ARG_SERVICE = "service"
    ARG_SELECTOR = "selector"
    ARG_PORT = "port"

    def __init__(self, subname):
        super(ServiceOpen, self).__init__(subname)

        self.args.append(PtrType(
            {"ref": StringType({"data": [0]}).toJson()}, typename=ServiceOpen.ARG_SERVICE))
        self.args.append(BufferType(
            {"data": int2bytes(0, 4)}, typename=ServiceOpen.ARG_SELECTOR))
        self.args.append(PtrType({"ref": ResourceType(
            {"name": "io_connect_t", "data": int2bytes(0, 8)}).toJson()}, typename=ServiceOpen.ARG_PORT))
        self.validate()

    @staticmethod
    def create(serviceName, selector, model_name):
        syscall = ServiceOpen(model_name)
        syscall.service = PtrType({"ref": StringType(
            {"data": [ord(e) for e in serviceName], "values": [serviceName]}).toJson()})
        syscall.selector = Constant(selector, 4, ServiceOpen.ARG_SELECTOR)
        port = ResourceType({"name": "%s_port" % model_name, "parent": "io_connect_t",
                             "data": int2bytes(0, 8)})
        syscall.port = PtrType({"ref": port.toJson()},
                               typename=ServiceOpen.ARG_PORT)
        syscall.validate()
        return syscall

    def validate(self):
        super(ServiceOpen, self).validate()

        self.service.dir = PtrDir.DirIn
        self.port.dir = PtrDir.DirOut
        return True

    @property
    def service(self):
        return self.args[0]

    @service.setter
    def service(self, val):
        self.args[0] = val

    @property
    def selector(self):
        return self.args[1]

    @selector.setter
    def selector(self, val):
        self.args[1] = val

    @property
    def port(self):
        return self.args[2]

    @port.setter
    def port(self, val):
        self.args[2] = val


class ServiceClose(Syscall):
    NAME = "syz_IOServiceClose"
    ARG_PORT = "port"

    def __init__(self, subName=""):
        super(ServiceClose, self).__init__(subName)

        self.args.append(BufferType(
            {"data": int2bytes(0, 8)}, typename=ServiceClose.ARG_PORT))

    @staticmethod
    def create(port):
        syscall = ServiceClose()
        syscall.port = BufferType(
            {"data": int2bytes(port, 8)}, typename=ServiceClose.ARG_PORT)
        return syscall

    @property
    def port(self):
        return self.args[0]

    @port.setter
    def port(self, val):
        self.args[0] = val


class IOConnectCallMethod(Syscall):
    """kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector, 
    const uint64_t *input, uint32_t inputCnt, const void *inputStruct, size_t inputStructCnt, 
    uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCnt);
    """
    NAME = "syz_IOConnectCallMethod"
    MAXIMUM_INPUTCNT = 0x10
    MAXIMUM_OUTPUTCNT = 0x10
    ARG_CONNECTION = "connection"
    ARG_SELECTOR = "selector"
    ARG_INPUT = "input"
    ARG_INPUT_CNT = "inputCnt"
    ARG_INPUTSTRUCT = "inputStruct"
    ARG_INPUTSTRUCT_CNT = "inputStructCnt"
    ARG_OUTPUT = "output"
    ARG_OUTPUT_CNT = "outputCnt"
    ARG_OUTPUTSTRUCT = "outputStruct"
    ARG_OUTPUTSTRUCT_CNT = "outputStructCnt"

    def __init__(self, subname):
        super(IOConnectCallMethod, self).__init__(subname)

        # mach_port_t connection
        self.args.append(
            ResourceType({"name": "io_connect_t", "data": int2bytes(0, 8)},
                         typename="connection")
        )
        # uint32_t selector
        self.args.append(BufferType(
            {"data": int2bytes(0, 4)}, typename=IOConnectCallAsyncMethod.ARG_SELECTOR))
        # uint64_t *input
        fields = []
        for i in range(IOConnectCallMethod.MAXIMUM_INPUTCNT):
            fields.append(BufferType({"data": [0xff]*8}, i*8).toJson())
        self.args.append(PtrType({"ref": StructType(
            {"fields": fields, "isArray": True}, 0).toJson()}, typename=IOConnectCallMethod.ARG_INPUT))
        # uint32_t inputCnt
        self.args.append(RangeType({
            "data": int2bytes(IOConnectCallMethod.MAXIMUM_INPUTCNT, 4),
            "min": 0,
            "max": IOConnectCallMethod.MAXIMUM_INPUTCNT,
            "stride": 1,
        }, typename=IOConnectCallMethod.ARG_INPUT_CNT))
        # void *inputStruct
        self.args.append(PtrType({"ref": BufferType(
            {"data": [0xff]*1024}).toJson()}, typename=IOConnectCallMethod.ARG_INPUTSTRUCT))
        # size_t inputStructCnt
        self.args.append(BufferType({"data": int2bytes(
            1024, 4)}, typename=IOConnectCallMethod.ARG_INPUTSTRUCT_CNT))
        # uint64_t *output
        fields = []
        for i in range(IOConnectCallMethod.MAXIMUM_OUTPUTCNT):
            fields.append(BufferType({"data": [0xff]*8}, i*8).toJson())
        self.args.append(
            PtrType({"ref": StructType({"fields": fields, "isArray": True}).toJson()},
                    typename=IOConnectCallMethod.ARG_OUTPUT)
        )
        # uint32_t *outputCnt
        self.args.append(
            PtrType({"ref": RangeType({
                "data": int2bytes(IOConnectCallMethod.MAXIMUM_OUTPUTCNT, 4),
                "min": 0,
                "max": IOConnectCallMethod.MAXIMUM_OUTPUTCNT,
                "stride": 1,
            }).toJson()},
                typename=IOConnectCallMethod.ARG_OUTPUT_CNT)
        )
        # void *outputStruct
        self.args.append(PtrType({"ref": BufferType(
            {"data": [0xff]*1024}).toJson()}, typename=IOConnectCallMethod.ARG_OUTPUTSTRUCT))
        # size_t *outputStructCnt
        self.args.append(PtrType({"ref": BufferType({"data": int2bytes(
            1024, 4)}).toJson()}, typename=IOConnectCallMethod.ARG_OUTPUTSTRUCT_CNT))

        self.validate()

    def validate(self):
        super(IOConnectCallMethod, self).validate()

        if self.input.type == "ptr":
            self.input.ref.isArray = True
            self.input.dir = PtrDir.DirIn
            self.inputCnt.path = [2]
            self.inputCnt.bitSize = 64
            # if self.inputCnt.type == "len":
            #     self.inputCnt.bitSize = 64
        if self.inputStruct.type == "ptr":
            self.inputStruct.dir = PtrDir.DirIn
            self.inputStructCnt.path = [4]
        if self.output.type == "ptr":
            self.output.ref.isArray = True
            self.output.dir = PtrDir.DirOut
        if self.outputCnt.type == "ptr":
            self.outputCnt.dir = PtrDir.DirIn
            self.outputCnt.ref.path = [6]
            self.outputCnt.ref.bitSize = 64
            # if self.outputCnt.ref.type == "len":
            #     self.outputCnt.ref.bitSize = 64
        if self.outputStruct.type == "ptr":
            self.outputStruct.dir = PtrDir.DirOut
        if self.outputStructCnt.type == "ptr":
            self.outputStructCnt.dir = PtrDir.DirIn
            self.outputStructCnt.ref.path = [8]
        return True

    @property
    def connection(self):
        return self.args[0]

    @connection.setter
    def connection(self, val):
        self.args[0] = val

    @property
    def selector(self):
        return self.args[1]

    @selector.setter
    def selector(self, val):
        self.args[1] = val

    @property
    def input(self):
        return self.args[2]

    @input.setter
    def input(self, val):
        self.args[2] = val

    @property
    def inputCnt(self):
        return self.args[3]

    @inputCnt.setter
    def inputCnt(self, val):
        self.args[3] = val

    @property
    def inputStruct(self):
        return self.args[4]

    @inputStruct.setter
    def inputStruct(self, val):
        self.args[4] = val

    @property
    def inputStructCnt(self):
        return self.args[5]

    @inputStructCnt.setter
    def inputStructCnt(self, val):
        self.args[5] = val

    @property
    def output(self):
        return self.args[6]

    @output.setter
    def output(self, val):
        self.args[6] = val

    @property
    def outputCnt(self):
        return self.args[7]

    @outputCnt.setter
    def outputCnt(self, val):
        self.args[7] = val

    @property
    def outputStruct(self):
        return self.args[8]

    @outputStruct.setter
    def outputStruct(self, val):
        self.args[8] = val

    @property
    def outputStructCnt(self):
        return self.args[9]

    @outputStructCnt.setter
    def outputStructCnt(self, val):
        self.args[9] = val


class IOConnectCallAsyncMethod(IOConnectCallMethod):
    NAME = "syz_IOConnectCallAsyncMethod"

    def __init__(self, subname):
        super(IOConnectCallAsyncMethod, self).__init__(subname)

    def assignNewName(self, prefix: str) -> str:
        self._counter += 1
        return f"async_{self.SubName}_{prefix}_{self._counter}"
