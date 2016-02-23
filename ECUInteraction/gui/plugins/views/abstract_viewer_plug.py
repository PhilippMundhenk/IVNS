

from gui.plugins.abstract_widget_plug import AbstractWidgetPlugin
import logging
from math import floor

class AbstractViewerPlugin(AbstractWidgetPlugin):
    '''
    This class is the base class for all Widgets that are inserted into
    the GUI via a Plug In
    '''
    def __init__(self, *args, **kwargs):
        AbstractWidgetPlugin.__init__(self, *args, **kwargs)
        
        self._VIEWER = True
        self.reader = None
        self.known = []
    
    def get_interpreters(self):
        ''' 
        each view has to specify which result interpreters
        they want to subscribe to
        '''
        logging.warn("NO Result Interpreter SPECIFIED FOR CLASS '%s'! Thus this viewer will not get any information." % self.__class__.__name__)
        return []
    
    def set_reader(self, reader):
        ''' sets the result reader that transmits the data to 
            the GUI '''
        self.reader = reader        
        self.reader.subscribe(self, 'update_gui', self.get_interpreters())
        
    def update_gui(self, interpreter_input):
        raise NotImplementedError('update_gui was not implemented by class %s' % self.__class__)

    def link_axis(self):
        '''this method returns a plot that will be linked to 
           the x Axis of the other plots'''
        return None

    def save(self):
        return []
    
    def _already_there(self, mon_input): 
        ''' handles duplicates'''
        if hash(mon_input) in self.known: 
            return True      
        self.known.append(hash(mon_input))
        if len(self.known) > 1000:
            del self.known[:floor(float(len(self.known)) / 2.0)]
        return False
    