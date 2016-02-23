from io_processing.result_interpreter.abst_result_interpreter import AbstractInterpreter, \
    InterpreterOptions
from io_processing.surveillance_handler import BufferHandler
import csv


class BufferInterpreter(AbstractInterpreter):
    
    def __init__(self, export_options=False, file_path=False): 
        AbstractInterpreter.__init__(self, export_options, file_path)
        
        self.file_path = file_path
        self.init_csv(file_path)
    
    def interprete_data(self, mon_inputs):
        
        if InterpreterOptions.CSV_FILE in self.export_options:
            for mon_input in mon_inputs:
                try:
                    
                    self.csv_writer.writerow([mon_input[0], mon_input[1], mon_input[3], mon_input[9]])
                except:
                    pass            
        
        # forward to connected device        
        if InterpreterOptions.CONNECTION in self.export_options:
            self._export_connection(mon_inputs)
    
    def get_handler(self):
        return [BufferHandler]

    def init_csv(self, filepath):        
        try:
#             idx = filepath[::-1].find('.')
#             filepath = filepath[:(-idx - 1)] + filepath[(-idx - 1):]
            self.csv_writer = csv.writer(open(filepath, 'w'), delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        except:
            pass
