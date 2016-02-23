
from PyQt4 import QtGui
from gui.main_window import MainWindow
import sys
from gui.direct_view_window import DirectViewWindow, DirectViewer

'''
Later configure from here in some code lines: GUI On GUI off, want to have view x and view y

maybe a api for gui ?

'''

q_app = QtGui.QApplication(sys.argv)       
gui = MainWindow()
# a = NewSimulationWindow(gui)
gui.show()
        
# sys.exit(q_app.exec_())