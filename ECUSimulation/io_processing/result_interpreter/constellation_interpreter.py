from io_processing.result_interpreter.abst_result_interpreter import AbstractInterpreter, \
    InterpreterOptions
from io_processing.surveillance_handler import ConstellationHandler


class ConstellationInterpreter(AbstractInterpreter):
    '''
    This class simply pushes the constellation to the ecus
    '''
    def __init__(self, export_options=False, file_path=False): 
        AbstractInterpreter.__init__(self, export_options, file_path)
        
        self.file_path = file_path
    
    def interprete_data(self, mon_inputs):

        # forward to connected device        
        if InterpreterOptions.CONNECTION in self.export_options:
            self._export_connection(mon_inputs)
    
    def get_handler(self):
        return [ConstellationHandler]
