'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''
from gui.plugins.abstract_widget_plug import AbstractWidgetPlugin

class AbstractSettingsPlugin(AbstractWidgetPlugin):
    '''
    This class is the base class for all Widgets that are inserted into
    the GUI via a Plug In
    '''
    
    def __init__(self, *args, **kwargs):
        AbstractWidgetPlugin.__init__(self, *args, **kwargs)
        
        self._SETTINGS = True
        
        self.monitored_obj = []