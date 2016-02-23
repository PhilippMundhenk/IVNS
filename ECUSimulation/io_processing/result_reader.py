'''
Created on 15 Jun, 2015

@author: artur.mrowca
'''   

class ResultReader(object):
    '''
    Is connected to the monitor and saves and manages 
    the results
    '''

    def __init__(self, monitor=None):   
        self._interpreters = {}  # each interpreter can exist once
        self.set_monitor(monitor)
        
    def enable_handler(self, interpreter_class, options=None, filepath=None):
        ''' the passed handler will be activated '''
        
        # check if it was already enabled
        if interpreter_class.__name__ in self._interpreters:
            return 

        # enable
        interpreter = interpreter_class(options, filepath)  
        interpreter.export_options = options
        interpreter.file_path = filepath
        self._interpreters[interpreter_class.__name__] = interpreter
        
        # monitor already set
        if self.monitor != None:
            handlers = interpreter.get_handler()
            self.monitor.subscribe(interpreter, 'interprete_data', handlers)
        
    def on_finish(self):
        ''' 
        called right after the simulation 
        e.g. used to save files after simulation 
        '''
        for ky in self._interpreters:
            try:
                self._interpreters[ky].on_finish()
            except:
                pass
        
    def set_monitor(self, monitor):
        ''' connects the monitors handlers to this reader '''
        
        # connect monitor
        self.monitor = monitor
        
        # connect specified interpreters
        for ky in self._interpreters:
            interpreter = self._interpreters[ky]
            self.monitor.subscribe(interpreter, 'interprete_data', interpreter.get_handler())        
    
    def subscribe(self, obj, func_name, interpreter_classes):
        
        for inter_class in interpreter_classes:
            # check if available else generate
            try:
                self._interpreters[inter_class.__name__]          
            except:
                self.enable_handler(inter_class)     
            
            # enable connection
            self._interpreters[inter_class.__name__].enable_connection()
                         
            # subscribe to this interpreter            
            self._interpreters[inter_class.__name__].subscribe(obj, func_name)
    
