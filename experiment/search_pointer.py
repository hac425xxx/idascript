from pydoc import ispackage
import idaapi
import idc
import idautils

def undefine_address(ea, sz):
    for i in range(sz):
        idaapi.del_items(ea + i, 1)

def add_dref(frm, to):
    idaapi.add_dref(frm, to, idaapi.dr_R)
    idaapi.add_dref(to, frm, idaapi.dr_R)

def is_pointer(ea):
    if idaapi.get_byte(ea) != 0xff and ea != 0:
        return True
    return False

def detect_pointer(start, end):
    ea = start
    while ea < end:
        v = idaapi.get_dword(ea)
        if is_pointer(v):
            undefine_address(ea, 4)
            idc.create_dword(ea)
            print("ea: 0x{:x} , value: 0x{:x}".format(ea, v))
            add_dref(ea, v)
        ea += 4

def main():
    for segment_ea in idautils.Segments():
        segment = idaapi.getseg(segment_ea)
        detect_pointer(segment.start_ea, segment.end_ea)

main()
