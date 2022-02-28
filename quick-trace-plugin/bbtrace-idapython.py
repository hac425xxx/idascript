# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\form.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QWidget
import idautils
import idaapi
import idc
from idaapi import *
import sys
import Queue
import re


class Window(QWidget):
    # 初始化
    def __init__(self):
        super(Window, self).__init__()


class Ui_Form(object):
    def __init__(self, manger):
        self.manger = manger

    def setupUi(self, Form):
        Form.setObjectName("Form")
        # Form.resize(1200, 800)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Form.sizePolicy().hasHeightForWidth())
        Form.setSizePolicy(sizePolicy)
        self.gridLayout_3 = QtWidgets.QGridLayout(Form)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.label_entry = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label_entry.setFont(font)
        self.label_entry.setObjectName("label_entry")
        self.gridLayout_2.addWidget(self.label_entry, 0, 0, 1, 1)
        self.entry_function = QtWidgets.QLineEdit(Form)
        self.entry_function.setObjectName("entry_function")
        self.gridLayout_2.addWidget(self.entry_function, 0, 1, 1, 1)
        self.label_depth = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label_depth.setFont(font)
        self.label_depth.setObjectName("label_depth")
        self.gridLayout_2.addWidget(self.label_depth, 0, 2, 1, 1)
        self.text_depth = QtWidgets.QLineEdit(Form)
        self.text_depth.setObjectName("text_depth")
        self.gridLayout_2.addWidget(self.text_depth, 0, 3, 1, 1)
        self.run_mode = QtWidgets.QCheckBox(Form)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.run_mode.setFont(font)
        self.run_mode.setObjectName("run_mode")
        self.gridLayout_2.addWidget(self.run_mode, 0, 4, 1, 1)
        self.gridLayout_3.addLayout(self.gridLayout_2, 0, 0, 1, 1)
        self.plainTextEdit = QtWidgets.QPlainTextEdit(Form)
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.gridLayout_3.addWidget(self.plainTextEdit, 1, 0, 1, 1)
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.get_bb_list_button = QtWidgets.QPushButton(Form)
        self.get_bb_list_button.setObjectName("get_bb_list_button")
        self.gridLayout.addWidget(self.get_bb_list_button, 0, 0, 1, 1)
        self.padding_label = QtWidgets.QLabel(Form)
        self.padding_label.setObjectName("padding_label")
        self.gridLayout.addWidget(self.padding_label, 0, 1, 1, 1)
        self.set_bblist_color_button = QtWidgets.QPushButton(Form)
        self.set_bblist_color_button.setObjectName("set_bblist_color_button")
        self.gridLayout.addWidget(self.set_bblist_color_button, 0, 2, 1, 1)
        self.gridLayout_3.addLayout(self.gridLayout, 2, 0, 1, 1)


        self.set_bblist_color_button.setVisible(False)
        self.padding_label.setVisible(False)

        self.get_bb_list_button.clicked.connect(
            lambda: self.manger.get_bblist_of_target(self))
        self.set_bblist_color_button.clicked.connect(
            lambda: self.manger.set_bblist_color(self))
        self.run_mode.stateChanged.connect(
            lambda: self.manger.switch_run_mode(self))

        self.plainTextEdit.setPlainText("填入BB列表")
        self.entry_function.setText("here")
        self.text_depth.setText("1")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "快速Trace工具"))
        self.label_entry.setText(_translate("Form", "入口函数"))
        self.label_depth.setText(_translate("Form", "调用深度"))
        self.run_mode.setText(_translate("Form", "染色模式"))
        self.get_bb_list_button.setText(_translate("Form", "获取BB列表"))
        self.padding_label.setText(_translate("Form", "            "))
        self.set_bblist_color_button.setText(_translate("Form", "BB染色"))


class FuncItem:
    def __init__(self, ea, depth, fc):
        self.address = ea

        self.parent = []
        self.child = []

        self.depth = depth

        self.fc = fc

    def __eq__(self, addr):
        # print "in __eq__"
        return self.address == addr


class BasicBlockManager:
    def __init__(self):
        self.bbmap = {}
        self.func_bblist_cache = {}

        self.func_cache_hitcont = 0
        self.bbmap_hitcount = 0

        self.cmt_re = re.compile("\[.*?\]")


    def reset_hitcount(self):
        self.func_cache_hitcont = 0
        self.bbmap_hitcount = 0

    def get_func_bblist(self, function):
        bblist = []

        if self.func_bblist_cache.has_key(function.startEA):
            self.func_cache_hitcont += 1
            return self.func_bblist_cache[function.startEA]

        try:
            flowchart = idaapi.FlowChart(function)
            # print("Function starting at 0x%x consists of %d basic blocks" % (function.startEA, flowchart.size))
            for bb in flowchart:
                self.bbmap[bb.startEA] = bb
                bblist.append(bb.startEA)
        except Exception as e:
            print e

        self.func_bblist_cache[function.startEA] = bblist

        # print "cur bbmap size:{}, func cache size: {}".format(len(self.bbmap), len(self.func_bblist_cache))

        return bblist

    def get_child_func_bblist(self, target, maxdepth=0xffff):

        bblist = []
        addr = target

        if isinstance(target, str):
            addr = idc.get_name_ea_simple(target)
        
        function = idaapi.get_func(addr)
        if function:
            addr = function.startEA
        else:
            print "{} is not in function".format(target)
            exit(0)

        # addr = get_name_ea(0, func_name)

        func_list = []
        func_queue = Queue.Queue()

        depth = 0

        func_item = FuncItem(addr, depth, function)

        func_list.append(func_item)
        func_queue.put(func_item)

        while not func_queue.empty():

            ff = func_queue.get()

            if ff.depth >= maxdepth:
                break

            # 遍历当前函数的所有call指令，获取调用的目标地址
            dism_addr = list(idautils.FuncItems(ff.address))
            for ea in dism_addr:
                if ida_idp.is_call_insn(ea):
                    callee = get_first_fcref_from(ea)
                    function = idaapi.get_func(callee)
                    if not function:
                        continue

                    func_start_ea = function.startEA
                    if func_start_ea in func_list:
                            continue

                    callee_name = get_func_name(func_start_ea)
                    print "0x{:X} call {}: 0x{:X}".format(ff.address, callee_name, callee)

                    func_item = FuncItem(func_start_ea, ff.depth + 1, function)
                    func_list.append(func_item)
                    func_queue.put(func_item)


        for ff in func_list:
            print "func addr: 0x{:X}, depth: {}".format(ff.address, ff.depth)
            bblist += self.get_func_bblist(ff.fc)

        return bblist

    def set_basic_block_color(self, bb, bg_color=0x00ff00):
        # print "try set color on 0x{:x}".format(bb.startEA)
        p = idaapi.node_info_t()
        p.bg_color = 0x00ff00  # green
        idaapi.set_node_info(bb._fc._q.bounds.start_ea,
                             bb.id, p, idaapi.NIF_BG_COLOR)

    def clear_basic_block_color(self, bb):
        idaapi.clr_node_info(bb._fc._q.bounds.start_ea,
                             bb.id, idaapi.NIF_BG_COLOR)

    def clear_bb_cmt(self, addr):
        raw_cmt = idc.get_cmt(addr, True)
        data = ""
        if raw_cmt:
            data = self.cmt_re.sub("", raw_cmt)
        idc.set_cmt(addr, data.strip(), True)

    def set_bb_cmt(self, addr, data):
        cmt = idc.get_cmt(addr, True)
        if cmt:
            idc.set_cmt(addr, "{} {}".format(cmt, data), True)
        else:
            idc.set_cmt(addr, " {}".format(data), True)

    def set_basic_block_list_color(self, bblist):
        imagebase = idaapi.get_imagebase()
        self.reset_hitcount()

        idx = 0
        for bb in bblist:

            bb_address = bb + imagebase
            try:
                next_bb_address = bblist[idx + 1] + imagebase
            except:
                next_bb_address = 0

            if self.bbmap.has_key(bb_address):
                self.bbmap_hitcount += 1
                idx += 1
                self.set_basic_block_color(self.bbmap[bb_address])
                if bb_address != 0:
                    self.set_bb_cmt(bb_address, "[next jump][{:X}]".format(next_bb_address))
                continue
            
            try:
                f = idaapi.get_func(bb_address)
                for block in idaapi.FlowChart(f):
                    self.bbmap[block.startEA] = block
            except Exception as e:
                print e

            if self.bbmap.has_key(bb_address):
                self.bbmap_hitcount += 1
                idx += 1
                self.set_basic_block_color(self.bbmap[bb_address])
                if bb_address != 0:
                    self.set_bb_cmt(bb_address, "[next jump][{:X}]".format(next_bb_address))
            else:
                print "can't found bb for 0x{:X}".format(bb_address)

        print "Set Color Done, bbmap hit count:{}!".format(self.bbmap_hitcount)

    def clear_bb_list_color(self, bblist):
        imagebase = idaapi.get_imagebase()
        self.reset_hitcount()

        for bb in bblist:

            bb_address = bb + imagebase

            if self.bbmap.has_key(bb_address):
                self.bbmap_hitcount += 1
                self.clear_basic_block_color(self.bbmap[bb_address])
                self.clear_bb_cmt(bb_address)
                continue
            try:
                f = idaapi.get_func(bb_address)
                for block in idaapi.FlowChart(f):
                    self.bbmap[block.startEA] = block
            except Exception as e:
                print e

            if self.bbmap.has_key(bb_address):
                self.bbmap_hitcount += 1
                self.clear_basic_block_color(self.bbmap[bb_address])
                self.clear_bb_cmt(bb_address)
            else:
                print "can't found bb for 0x{:X}".format(bb_address)

        
        print "Clear Color Done, bbmap hitcount:{}!".format(self.bbmap_hitcount)


class BBTraceManger(PluginForm):
    def __init__(self):
        self.bb_manger_list = []
        self.basic_block_manger = BasicBlockManager()
        self.imagebase = idaapi.get_imagebase()
        self.is_color_mode = False

        super(BBTraceManger, self).__init__()

    def switch_run_mode(self, ui):

        self.is_color_mode = ui.run_mode.isChecked()
        _translate = QtCore.QCoreApplication.translate
        if self.is_color_mode:
            # print("color mode")
            ui.padding_label.setVisible(True)
            ui.set_bblist_color_button.setVisible(True)
            ui.get_bb_list_button.setText(_translate("Form", "清除BB的颜色"))
        else:
            ui.set_bblist_color_button.setVisible(False)
            ui.padding_label.setVisible(False)
            ui.get_bb_list_button.setText(_translate("Form", "获取BB列表"))

    def clear_bblist_color(self, bbs):
        bblist = []

        for bb in bbs.split(","):
            if bb.strip() != "":
                bblist.append(int(bb, 16))

        self.basic_block_manger.clear_bb_list_color(bblist)

        idaapi.request_refresh(0xFFFFFFFF)

    def set_bblist_color(self, ui):
        bbs = ui.plainTextEdit.toPlainText()
        entry = ui.entry_function.text()
        depth = ui.text_depth.text()
        mode = ui.run_mode.isChecked()

        bblist = []

        for bb in bbs.split(","):
            if bb.strip() != "":
                bblist.append(int(bb, 16))

        self.basic_block_manger.set_basic_block_list_color(bblist)

        idaapi.request_refresh(0xFFFFFFFF)

    def get_bblist_of_target(self, ui):
        entry = ui.entry_function.text()
        depth = ui.text_depth.text()
        mode = ui.run_mode.isChecked()

        if not self.is_color_mode:
            self.basic_block_manger.reset_hitcount()
            addr = 0
            if entry == "here":
                addr = idc.here()
            else:
                try:
                    addr = int(entry, 16)
                except:
                    addr = idc.here()

            bblist = self.basic_block_manger.get_child_func_bblist(addr, int(depth))

            # print("bblist:{}, entry:{}, depth:{}, mode:{}".format(bblist, entry, depth, mode))
            data = ""
            for bb in bblist:
                data += "0x{:X},".format(bb - self.imagebase)

            ui.plainTextEdit.setPlainText(data[:-1])

            print("function cache hit count: {}, bb hit count: {}".format(self.basic_block_manger.func_cache_hitcont, self.basic_block_manger.bbmap_hitcount))
        else:
            self.clear_bblist_color(ui.plainTextEdit.toPlainText())

    def new_win(self):
        win = Window()
        win.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)  # 窗口置顶
        ui = Ui_Form(self)
        ui.setupUi(win)
        win.show()

        self.bb_manger_list.append(win)

    def new_window(self):
        #app = QtWidgets.QApplication(sys.argv)

        self.new_win()

        # sys.exit(app.exec_())

    def OnCreate(self, form):
        """
        Called when the widget is created
        """

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()


    def PopulateForm(self):
        ui = Ui_Form(self)
        ui.setupUi(self.parent)

    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        pass


class bbtrace_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "A plugin for quick trace"

    help = "https://gitee.com/hac425/idascript/tree/master/quick-trace-plugin"
    wanted_name = "quick trace plugin"
    wanted_hotkey = "Shift-Z"

    def init(self):
        self.manger = BBTraceManger()
        
        idaapi.msg("quick trace plugin inited!\n")

        return idaapi.PLUGIN_OK

    def run(self, arg):
        # self.manger.new_window()
        self.manger.Show("Quick Trace Plugin")

    def term(self):
        idaapi.msg("quick trace plugin exit!\n")

def PLUGIN_ENTRY():
    return bbtrace_t()
