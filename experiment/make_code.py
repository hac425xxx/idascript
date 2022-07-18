import idaapi
import idc

def define_function(addr, name=""):
    if addr & 1:
        addr -= 1
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 1, idaapi.SR_user)
    else:
        idaapi.split_sreg_range(addr, idaapi.str2reg("T"), 0, idaapi.SR_user)
    
    if idaapi.create_insn(addr):
        if idc.add_func(addr):
            if name != "":
                idaapi.set_name(addr, name,idaapi.SN_FORCE)
        return True
    return False

def main():
    ea = idaapi.get_imagebase()

    while True:
        ea = idaapi.next_unknown(ea, idaapi.BADADDR)
        if ea == idaapi.BADADDR:
            break
        
        print("ea: 0x{:x}".format(ea))
        insn_len = idaapi.create_insn(ea)
        if insn_len:
            # addr = ea
            # while addr < ea + insn_len:
            #     dis = idc.generate_disasm_line(ea, 0).lower()
            #     if "nop" not in dis:
            #         break
            idc.add_func(ea)


main()