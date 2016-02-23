from io_processing.result_interpreter.abst_result_interpreter import AbstractInterpreter, \
    InterpreterOptions
from io_processing.surveillance_handler import CanBusHandler
import csv
from math import floor

from tools.ecu_logging import ECULogger
from config import can_registration
import logging


class CanBusInterpreter(AbstractInterpreter):
    
    def __init__(self, export_options=False, file_path=False): 
        AbstractInterpreter.__init__(self, export_options, file_path)
        
        self.file_path = file_path
        self._init_csv(file_path)
        self.known = []
        
        self._bus_ids = []
        self.bytes_trans = {}
        self.last_time = 0
        
        # counting msgs
        self.no_simple_msgs = {}  # depending on stream
        self.no_auth_msgs = {}  # per ECU
        self.no_str_msgs = {}  # per Stream

        # countings segments
        self.no_simple_msgs_seg = {}  # depending on stream
        self.no_auth_msgs_seg = {}  # per ECU
        self.no_str_msgs_seg = {}  # per Stream
        
        # counting bytes 
        self.no_simple_msgs_bytes = {}  # depending on stream
        self.no_auth_msgs_bytes = {}  # per ECU
        self.no_str_msgs_bytes = {}  # per Stream
    
    def get_handler(self):
        return [CanBusHandler]
    
    def interprete_data(self, data):
        
        # Initialize
        cur_time, mon_inputs, bus_info = data[0], data[1], []
        
        
        for mon_input in mon_inputs:        
                
            try:
                    
                # CSV Export
                if InterpreterOptions.CSV_MSG_FILE in self.export_options:                    
                    self._export_csv_1(mon_input)

                # add information
                bus_info.append([mon_input[0], mon_input[1], mon_input[3], mon_input[9], mon_input[8], mon_input[2]])
                self.bytes_trans[mon_input[1]] += mon_input[6]
                
                # count appearances(Messages, Bytes, Segments) per Bus and Comp// Counting Segments!
                self._append_apearances(mon_input)
          
            except KeyError:
                self.bytes_trans[mon_input[1]] = mon_input[6]
                self._append_apearances(mon_input)   
                
        # calculate bus load/ avg. datarate
        try:
            if cur_time >= self.last_time:
                info = self._calc_datarate_export(cur_time, self.last_time, self.bytes_trans)
            else:
                info = []
        except: 
            pass
             
        # forward to connected device        
        if InterpreterOptions.CONNECTION in self.export_options:
            self._export_connection([info, bus_info])
                
        # reset
        self._reset_and_print(cur_time)
    
    def on_finish(self, cur_time=False):
        ''' Export the number of ECU Advertisements/ Stream Authorization/ Simple Messages'''

        if InterpreterOptions.TXT_FILES in self.export_options:
            self._export_txt_file(cur_time)
            
    def _export_txt_file(self, cur_time):

        txt_lines = []
        
        if cur_time: txt_lines.append("-------------- Results after simulation time: %s -------------- " % cur_time)
        
        txt_lines.append(self._pretty_can_str("Number of sent Stream Authorization Messages", self.no_str_msgs, "Messages"))
        txt_lines.append(self._pretty_bus_comp("Number of sent ECU Authentication Messages", self.no_auth_msgs, "Messages"))
        txt_lines.append(self._pretty_can_str("Number of sent Simple Messages", self.no_simple_msgs, "Messages"))
        
        txt_lines.append(self._pretty_can_str("Number of sent Stream Authorization Segments", self.no_str_msgs_seg, "Segments"))
        txt_lines.append(self._pretty_bus_comp("Number of sent ECU Authentication Segments", self.no_auth_msgs_seg, "Segments"))
        txt_lines.append(self._pretty_can_str("Number of sent Simple Segments", self.no_simple_msgs_seg, "Segments"))
        
        txt_lines.append(self._pretty_can_str("Number of sent Stream Authorization Bytes", self.no_str_msgs_bytes, "Bytes"))
        txt_lines.append(self._pretty_bus_comp("Number of sent ECU Authentication Bytes", self.no_auth_msgs_bytes, "Bytes"))
        txt_lines.append(self._pretty_can_str("Number of sent Simple Bytes", self.no_simple_msgs_bytes, "Bytes"))
        
        try:
            out_txt = "\n\n".join(txt_lines)
            idx = self.file_path[::-1].find('.')
            file_path = self.file_path[:(-idx - 1)] + "_timings_ecus.txt"
            
            with open(file_path, "w") as text_file:
                text_file.write(out_txt)
        except:
            pass

    
    def _append_apearances(self, mon_input):
        '''raises the counter of appeared messages'''
        if mon_input[3] == 'MonitorTags.CB_PROCESSING_MESSAGE':
            if mon_input[4] in can_registration.ECU_AUTH_MESSAGES:
                self._inc_set(self.no_auth_msgs_seg, mon_input[1], mon_input[2], 1)                
                if mon_input[9].count('0') == len(mon_input[9]):                                                    
                    self._inc_set(self.no_auth_msgs_bytes, mon_input[1], mon_input[2], len(mon_input[9]))                                
                else:
                    self._inc_set(self.no_auth_msgs_bytes, mon_input[1], mon_input[2], mon_input[6])   
                    self._inc_set(self.no_auth_msgs, mon_input[1], mon_input[2], 1)
                
            elif mon_input[4] in can_registration.STREAM_AUTH_MESSAGES:
                self._inc_set(self.no_str_msgs_seg, mon_input[1], mon_input[7], 1)                
                if mon_input[9].count('0') == len(mon_input[9]):                    
                    self._inc_set(self.no_str_msgs_bytes, mon_input[1], mon_input[7], len(mon_input[9]))   
                else:
                    self._inc_set(self.no_str_msgs, mon_input[1], mon_input[7], 1)  
                    self._inc_set(self.no_str_msgs_bytes, mon_input[1], mon_input[7], mon_input[6])  

            else:  
                self._inc_set(self.no_simple_msgs_seg, mon_input[1], mon_input[4], 1)               
                if mon_input[9].count('0') == len(mon_input[9]):                      
                    self._inc_set(self.no_simple_msgs_bytes, mon_input[1], mon_input[4], len(mon_input[9]))
                else:
                    self._inc_set(self.no_simple_msgs, mon_input[1], mon_input[4], 1)  
                    self._inc_set(self.no_simple_msgs_bytes, mon_input[1], mon_input[4], mon_input[6])

    def _calc_datarate_export(self, cur_time, last_time, bytes_trans):
        ''' calculates the datarate and writes it to the file'''
        try:
            datarate = {}
            info = {}
            for ky in bytes_trans:
                datarate[ky] = float(bytes_trans[ky]) / (cur_time - last_time)
                
                info[ky] = [cur_time, ky, datarate[ky] / 1000.0]
                
                if InterpreterOptions.CSV_DR_FILE in self.export_options:
                    try:
                        self.csv_writer.writerow(["BUS DATARATE", info[ky][0], info[ky][1], info[ky][2]])
                    except:
                        ECULogger().log_traceback()
                
            return info
        except:
            pass

    def _export_csv_1(self, mon_input):
        
        self.csv_writer.writerow(["BUS MESSAGES", mon_input[0], mon_input[1], mon_input[3], mon_input[9]])

    def _inc_set(self, dict_inc, ky, ky2, stp):
        ''' increases the value of the dictionary at
            [ky][ky2] '''
        try:
            dict_inc[ky]
        except:
            dict_inc[ky] = {}            
        try:
            dict_inc[ky][ky2] += stp
        except:
            dict_inc[ky][ky2] = stp
    
    def _extend_ids(self, bus_id):
        ''' add to dict this bus'''
        if bus_id not in self._bus_ids:
            self._bus_ids.append(bus_id)
            self.bytes_trans[bus_id] = 0
    
    def _init_csv(self, filepath):        
        try:
            idx = filepath[::-1].find('.')
            filepath = filepath[:(-idx - 1)] + filepath[(-idx - 1):]   
            self.csv_writer = csv.writer(open(filepath, 'w'), delimiter=',')
                
            # Headline
            self.csv_writer.writerow(["Information Type", "Time", "Bus ID", "Monitor Tag/ Datarate", "Unique Message ID"])
                
        except:
            pass  # logging.error("CAN Bus Interpreter - CSV: Could not initialize filepath: %s" % filepath)


    def _pretty_can_str(self, intro_txt, comp_cat_dict, units=""):
        try:
            hash_line = "##########################################################################################"
            newline = "\n"
            tab = "\t"
            template = "\n\n\tBus Id: \t%s\n\tStream: \t%s\n\tValue: \t\t%s %s"
            
            res_str = hash_line + newline + tab + tab + intro_txt + newline + hash_line
            
            for comp in comp_cat_dict.keys():
                try:
                    for cat in comp_cat_dict[comp].keys():
                        try:
                            res_str += newline
                            res_str += (template % (comp, cat, comp_cat_dict[comp][cat], units))
                        except:
                            pass
                except:
                    pass
                
            return res_str 
        except:
            ""
            
    def _pretty_bus_comp(self, intro_txt, comp_cat_dict, units=""):
        try:
            hash_line = "##########################################################################################"
            newline = "\n"
            tab = "\t"
            template = "\n\n\tBus Id: \t%s\n\tSender Id: \t%s\n\tValue: \t\t%s %s"
            
            res_str = hash_line + newline + tab + tab + intro_txt + newline + hash_line
            
            for comp in comp_cat_dict.keys():
                try:
                    for cat in comp_cat_dict[comp].keys():
                        try:
                            res_str += newline
                            res_str += (template % (comp, cat, comp_cat_dict[comp][cat], units))
                        except:
                            pass
                except:
                    pass
                
            return res_str 
        except:
            ""
            
    def _reset_and_print(self, cur_time):
        self.bytes_trans = {}
        self._bus_ids = []    
        self.last_time = cur_time        
        
        # print current results
        self.on_finish(cur_time)
    
