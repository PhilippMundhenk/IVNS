'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''

from gui.plugins.settings.abstract_settings_plug import AbstractSettingsPlugin
from PyQt4 import QtGui
from PyQt4.Qt import QWidget

class StandardSettingsPlugin(AbstractSettingsPlugin):
    '''
    This class is the base class for all Widgets that are inserted into
    the GUI via a Plug In
    '''

    def __init__(self, *args, **kwargs):
        AbstractSettingsPlugin.__init__(self, *args, **kwargs)
    
        self._SETTINGS = False#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    
    def get_combobox_name(self):
        return "General Settings"
        
    def get_widget(self, parent):        
        return StandardSettingsPluginGUI(parent)
    
class StandardSettingsPluginGUI(QWidget):
    
    def __init__(self, *args, **kwargs):
        QWidget.__init__(self, *args, **kwargs)
        
        self.create_widgets()
        
        
    def create_widgets(self):   
        vbox = QtGui.QVBoxLayout()        
        label = QtGui.QLabel()
        label.setText("B")        
        vbox.addWidget(label)
        self.setLayout(vbox)