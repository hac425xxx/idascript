import gdb

BB_LIST = []
BreakList = []
BBTRACE = []


class TraceBreakpoint(gdb.Breakpoint):
    def __init__(self, name, bb_offset):
        super(TraceBreakpoint, self).__init__(
            name, gdb.BP_BREAKPOINT, internal=False)
        self.bb = bb_offset
        # print("Setbp on {}".format(name))

    def stop(self):
        global BBTRACE
        # print("0x{:x} catch!".format(self.bb))
        BBTRACE.append(self.bb)
        return False


class BBTraceCommand(gdb.Command):
    def __init__(self):
        super(BBTraceCommand, self).__init__("bbtrace", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        global BreakList
        argv = gdb.string_to_argv(args)
        argc = len(argv)

        if argc < 2:
            print("bbtrace imagebase bblist")
            return

        imagebase = int(argv[0], 16)
        bblist = argv[1].split(",")

        for bb in bblist:
            addr = int(bb, 16)
            BreakList.append(TraceBreakpoint(
                "*0x{:x}".format(imagebase + addr), addr))


class ClearBBtrace(gdb.Command):
    def __init__(self):
        super(ClearBBtrace, self).__init__("bbtrace_disable", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        global BreakList
        for bp in BreakList:
            bp.delete()

        BreakList = []


class DumpBBTrace(gdb.Command):
    def __init__(self):
        super(DumpBBTrace, self).__init__("bbtrace_dump", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        global BBTRACE
        data = ""
        for bb in BBTRACE:
            # print("0x{:x}".format(bb))
            data += "0x{:x},".format(bb)

        print(data[:-1])


BBTraceCommand()
ClearBBtrace()
DumpBBTrace()
