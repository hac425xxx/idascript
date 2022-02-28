# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'jumptookit.ui'
#
# Created by: PyQt5 UI code generator 5.13.0
#
# WARNING! All changes made in this file will be lost!


import imp
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication, QWidget
from PyQt5.QtCore import Qt
import idc
import idaapi
import os
import sys


if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding("utf-8")


last_debugger_base = 0


class Ui_TookitWidget(object):

    def __init__(self):

        global last_debugger_base

        self.debug_base_addr = last_debugger_base
        self.debug_addr_disabled = False
        self.mode = 1 # 0 ida offset to debug addr , 1 debug addr to ida offset

        self.imagebase = idaapi.get_imagebase()
        

    def setupUi(self, TookitWidget):
        
        TookitWidget.set_tookit_widgetui(self)
    
        TookitWidget.setObjectName("TookitWidget")

        # 整个框的大小
        TookitWidget.resize(480, 140)
        TookitWidget.setAutoFillBackground(True)
        
        # 调试器基地址输入框
        self.dbg_addr = QtWidgets.QLineEdit(TookitWidget)
        self.dbg_addr.setGeometry(QtCore.QRect(160, 20, 200, 31))
        self.dbg_addr.setObjectName("dbg_addr")
        self.dbg_base_label = QtWidgets.QLabel(TookitWidget)
        self.dbg_base_label.setGeometry(QtCore.QRect(10, 20, 140, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.dbg_base_label.sizePolicy().hasHeightForWidth())
        self.dbg_base_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.dbg_base_label.setFont(font)
        self.dbg_base_label.setLineWidth(1)
        self.dbg_base_label.setWordWrap(False)
        self.dbg_base_label.setObjectName("dbg_base_label")
        self.debug_button = QtWidgets.QPushButton(TookitWidget)
        self.debug_button.setGeometry(QtCore.QRect(380, 20, 71, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.debug_button.setFont(font)
        self.debug_button.setObjectName("debug_button")

        self.debug_button.clicked.connect(self.set_debug_base)


        self.jump_button = QtWidgets.QPushButton(TookitWidget)
        self.jump_button.setGeometry(QtCore.QRect(380, 80, 71, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.jump_button.setFont(font)
        self.jump_button.setObjectName("jump_button")
        
        self.jump_button.clicked.connect(self.get_result)
        
        self.jump_offset_label = QtWidgets.QLabel(TookitWidget)
        self.jump_offset_label.setGeometry(QtCore.QRect(10, 80, 140, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.jump_offset_label.sizePolicy().hasHeightForWidth())
        self.jump_offset_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.jump_offset_label.setFont(font)
        self.jump_offset_label.setLineWidth(1)
        self.jump_offset_label.setWordWrap(False)
        self.jump_offset_label.setObjectName("jump_offset_label")
        
        
        self.jump_offset = QtWidgets.QLineEdit(TookitWidget)
        self.jump_offset.setGeometry(QtCore.QRect(160, 80, 200, 31))
        self.jump_offset.setObjectName("jump_offset")
        
        self.jump_offset.editingFinished.connect(self.get_result)

        self.dbg_addr.setText("0x{:x}".format(self.debug_base_addr))

        self.retranslateUi(TookitWidget)
        QtCore.QMetaObject.connectSlotsByName(TookitWidget)

    def get_module_name(self):
        fpath = idaapi.get_input_file_path()
        return os.path.basename(fpath)

    def retranslateUi(self, TookitWidget):
        _translate = QtCore.QCoreApplication.translate
        TookitWidget.setWindowTitle(_translate("TookitWidget", self.get_module_name()))
        self.dbg_base_label.setText(_translate("TookitWidget", "调试基地址"))
        self.debug_button.setText(_translate("TookitWidget", "设置"))
        self.jump_button.setText(_translate("TookitWidget", "跳转"))
        self.jump_offset_label.setText(_translate("TookitWidget", "调试地址"))

    def get_result(self):
        if self.mode == 1:
            try:
                offset = int(self.jump_offset.text(), 16) - self.debug_base_addr
                addr = self.imagebase + offset
                idc.jumpto(addr)
            except Exception as e:
                print("input:{}, error:{}".format(self.jump_offset.text(), str(e)))
                pass
        else:
            try:
                offset = idc.here() - self.imagebase
                # text = hex(self.debug_base_addr + offset)
                # text = text.replace('L', '')
                text = "0x{:x}".format(self.debug_base_addr + offset)
                self.jump_offset.setText(text)

                clipboard = QApplication.clipboard()
                clipboard.setText(text)
            except Exception as e:
                print(e)
                pass
        

    def set_debug_base(self):

        global last_debugger_base

        if self.debug_addr_disabled:
            self.dbg_addr.setEnabled(True)
            self.debug_addr_disabled = False
            return
        
        try:
            self.debug_base_addr = int(self.dbg_addr.text(), 16)
            last_debugger_base = self.debug_base_addr

            idaapi.msg(hex(self.debug_base_addr) + "\n")
            self.dbg_addr.setEnabled(False)
            self.debug_addr_disabled = True
        except Exception as e:
            print("set failed: {}".format(str(e)))

    # enter 按下时触发
    def enter_pressed(self): 
        self.get_result()       
        

class Window(QWidget):
    # 初始化
    def __init__(self):
        super(Window, self).__init__()
        
    def set_tookit_widgetui(self, tookit_widgetui):
        self.tookit_widgetui = tookit_widgetui
    
    def change_ui(self):
        _translate = QtCore.QCoreApplication.translate
        if self.tookit_widgetui.mode==1:
            # self.setWindowTitle(_translate("TookitWidget", "IDA->DBG"))
            self.tookit_widgetui.jump_button.setText(_translate("TookitWidget", "计算"))
            self.tookit_widgetui.mode = 0
        else:
            # self.setWindowTitle(_translate("TookitWidget", "DBG->IDA"))
            self.tookit_widgetui.jump_button.setText(_translate("TookitWidget", "跳转"))
            self.tookit_widgetui.mode = 1          


    # 检测键盘回车按键，函数名字不要改，这是重写键盘事件
    def keyPressEvent(self, event):
        # 这里event.key（）显示的是按键的编码
        # print("按下：" + str(event.key()))
        # 举例，这里Qt.Key_A注意虽然字母大写，但按键事件对大小写不敏感
        if (event.key() == Qt.Key_Escape):
            # print('测试：ESC')
            self.tookit_widgetui.jump_offset.clearFocus()
            self.tookit_widgetui.dbg_addr.clearFocus()
            
        
        if (event.key() == Qt.Key_A):
            print('测试：A')
        # 当需要组合键时，要很多种方式，这里举例为“shift+单个按键”，也可以采用shortcut、或者pressSequence的方法。
        if (event.key() == Qt.Key_P):
            if QApplication.keyboardModifiers() == Qt.ShiftModifier:
                print("shift + p")
            else :
                print("p")

        if (event.key() == Qt.Key_O) and QApplication.keyboardModifiers() == Qt.ShiftModifier:
            print("shift + o")

    # 响应鼠标事件
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            # print("鼠标左键点击")
            pass
        elif event.button() == Qt.RightButton:
            # print("鼠标右键点击")
            self.change_ui()
        elif event.button() == Qt.MidButton:
            # print("鼠标中键点击")
            pass

class TookitManger:
    def __init__(self):
        self.tookit_list = []
        self.hotkey_ctx = None
        self.hotkey_ctx = idaapi.add_hotkey("Shift-V", self.new_window)
        if self.hotkey_ctx is None:
            print("Failed to register hotkey!")
        else:
            print("Hotkey registered!")


    def new_window(self):
        TookitWidget = Window()
        # TookitWidget.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)  # 窗口置顶
        TookitWidget.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint | QtCore.Qt.WindowCloseButtonHint)
        ui = Ui_TookitWidget()
        ui.setupUi(TookitWidget)
        TookitWidget.show()
        self.tookit_list.append(TookitWidget)


class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "hac425"
    wanted_hotkey = ""

    help = "shift+v"
    wanted_name = "IDA Jump Tookit Plugin"

    def init(self):
        self.manger = TookitManger()
        idaapi.msg("init() called!\n")

        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.manger.new_window()

    def term(self):
        idaapi.msg("term() called!\n")

def PLUGIN_ENTRY():
    return myplugin_t()




