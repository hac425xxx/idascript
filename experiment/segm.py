import idaapi


def test():
    idaapi.set_segm_end(0x180000, 0x1c6000,
                        idaapi.SEGMOD_KEEP | idaapi.SEGMOD_SILENT)
    idaapi.add_segm(0, 0x1c6000, 0x1c6000 + 0x1000, ".data", "DATA")
