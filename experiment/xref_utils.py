import idaapi

def add_dref(frm, to):
    idaapi.add_dref(frm, to, idaapi.dr_R)
    idaapi.add_dref(to, frm, idaapi.dr_R)