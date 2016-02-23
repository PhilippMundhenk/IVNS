'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''
from gui.plugins.views.abstract_viewer_plug import AbstractViewerPlugin
from PyQt4.Qt import QWidget
from PyQt4 import QtGui
import logging



class TestViewPlugin(AbstractViewerPlugin):
    '''
    This class is the base class for all Widgets that are inserted into
    the GUI via a Plug In
    '''

    def __init__(self, *args, **kwargs):
        AbstractViewerPlugin.__init__(self, *args, **kwargs)
        self._VIEWER = False
        
    def get_combobox_name(self):
        return "Test View"

    def get_widget(self, parent):
        wid = QWidget(parent)        
        vbox = QtGui.QVBoxLayout()        
        label = QtGui.QLabel()
        label.setText("V")
        vbox.addWidget(label)      
        wid.setLayout(vbox)
        return wid
    
    def update_gui(self, lst_vals):         
        ''' 1. Get new values from the monitor '''
        i = 0
#         logging.info('1111111111111111111111111111111')
        
        
