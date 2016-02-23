from enum import Enum
from PyQt4.Qt import QObject
from PyQt4 import QtCore
from math import floor

class AbstractInterpreter(QObject):
    
    publish_infos_sig = QtCore.pyqtSignal(list)
    
    def __init__(self, export_options=False, file_path=False, env_spec=None):   
        QObject.__init__(self)
        self.export_options = []  # list of ExportOptions
        self.file_path = file_path
        self._recs = []
        self.known = []
    
    def enable_connection(self):
        ''' enables the connectoin if not 
            already enabled'''

        if self.export_options == None:
            self.export_options = []

        if InterpreterOptions.CONNECTION not in self.export_options:
            self.export_options.append(InterpreterOptions.CONNECTION)
    
    def get_handler(self):
        ''' 
            returns the handler classes that will send their
            data to this interpreter
        '''
        return []
    
    def interprete_data(self, mon_inputs):
        ''' is invoked in certain time 
            intervals by the monitor'''
        raise NotImplementedError("The method interprete_data was not implemented in class %s " % self.__class__.__name__)
   
    def on_finish(self):
        '''
        This method is invoked after the simulation finished.
        It is used to export data that was gathered to a file
        '''
        print("%s finish!" % self.__class__.__name__)
        
    def subscribe(self, obj, func_name):        
        self._recs.append(obj)
        exec('self.publish_infos_sig.connect(obj.%s)' % func_name)
        
    def _export_connection(self, export_input):
        ''' every time that the data was interpreted the 
            information is published to all connected receivers
            that subscribed to this interpreter
            
            e.g. a specific GUI Plugin
            '''
        self.publish_infos_sig.emit(export_input)
    
class InterpreterOptions(Enum):
    
    CONNECTION = 1    
    CSV_FILE = 2
    CSV_PER_COMP_FILE = 2
    PGF_PLOT_FILE = 3
    TIMING_FILE = 4
    TXT_FILES = 5
    CSV_MSG_FILE = 6
    CSV_DR_FILE = 7
    
