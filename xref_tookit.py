import imp
from multiprocessing.spawn import import_main_path
from PyQt5.QtWidgets import (
    QWidget, QPushButton, QLineEdit, QInputDialog, QApplication, QLabel)
import idaapi
import idc

class CustomDialog(QWidget):

    def __init__(self):
        super().__init__()

    def get_refence_ea(self):
        text, ok = QInputDialog.getText(self, 'add xref from current ea', 'ref ea:', text = hex(idaapi.get_dword(idc.here())))
        try:
            if ok:
                return int(text, 16)
        except:
            print("input {} err!".format(text))

        return -1
            

def add_ref(frm, to):
    idaapi.add_dref(frm, to, idaapi.dr_R)
    idaapi.add_dref(to, frm, idaapi.dr_R)


class RefenceManger:
    def __init__(self):
        self.tookit_list = []
        self.hotkey_ctx = None
        self.hotkey_ctx = idaapi.add_hotkey("Alt-X", self.set_reference)
        if self.hotkey_ctx is None:
            print("Failed to register hotkey!")
        else:
            print("Hotkey registered!")

        self.cd = CustomDialog()


    def set_reference(self):
        ref_ea = self.cd.get_refence_ea()
        if ref_ea != -1:
            print("ea:0x{:x}".format(ref_ea))
            add_ref(idc.here(), ref_ea)


# r = RefenceManger()
# r.set_reference()

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "hac425"
    wanted_hotkey = ""

    help = "alt+x"
    wanted_name = "IDA Xref Tookit"

    def init(self):
        self.manger = RefenceManger()
        idaapi.msg("ida xref tookit init!\n")

        return idaapi.PLUGIN_OK

    def run(self, arg):
        # self.manger.new_window()
        pass

    def term(self):
        idaapi.msg("ida xref  term !\n")

def PLUGIN_ENTRY():
    return myplugin_t()






