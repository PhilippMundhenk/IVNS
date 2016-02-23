'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''
from gui.plugins.views.abstract_viewer_plug import AbstractViewerPlugin
from PyQt4.Qt import QWidget
from PyQt4 import QtGui
import pyqtgraph as pg
import numpy as np
from numpy.core.defchararray import isnumeric
from config import can_registration
from io_processing.surveillance_handler import MonitorTags, MonitorInput
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter
from tools.general import General
from uuid import UUID
from math import floor


class ECUShowAxis(pg.AxisItem):
    
    def __init__(self, orientation, *args):
        pg.AxisItem.__init__(self, orientation, *args)
        
        self.lanes_map = {}  # key: number, value: text 
        
    
    def tickValues(self, minVal, maxVal, size):
        
        minVal, maxVal = sorted((minVal, maxVal))
        

        minVal *= self.scale  
        maxVal *= self.scale
        # size *= self.scale
            
        ticks = []
        tickLevels = self.tickSpacing(minVal, maxVal, size)
        allValues = np.array([])
        for i in range(len(tickLevels)):
            spacing, offset = tickLevels[i]
            spacing = 1
            # # determine starting tick
            start = (np.ceil((minVal - offset) / spacing) * spacing) + offset
            
            # # determine number of ticks
            num = int((maxVal - start) / spacing) + 1
            values = (np.arange(num) * spacing + start) / self.scale
            # # remove any ticks that were present in higher levels
            # # we assume here that if the difference between a tick value and a previously seen tick value
            # # is less than spacing/100, then they are 'equal' and we can ignore the new tick.
            values = list(filter(lambda x: all(np.abs(allValues - x) > spacing * 0.01), values))
            
            allValues = np.concatenate([allValues, values])
            ticks.append((spacing / self.scale, values))
            
        if self.logMode:
            return self.logTickValues(minVal, maxVal, size, ticks)
            
        return ticks
    
    def tickStrings(self, values, scale, spacing):
        strns = []
        for x in values:
            try:
                text = self.lanes_map[int(x)]
            except:
                text = ""
            strns.append(text)

        return strns
    

class EventlineViewPlugin(AbstractViewerPlugin):

    def __init__(self, *args, **kwargs):
        AbstractViewerPlugin.__init__(self, *args, **kwargs)
        
    def get_combobox_name(self):
        return "Chain of events"

    def get_widget(self, parent):
        self.gui = EventlineViewPluginGUI(parent)
        return self.gui
    
    def get_interpreters(self):
        return [EventlineInterpreter]
    
    def link_axis(self):
        return self.gui.plot
        
    def load(self, data):
        self.gui.load(data)
    
    def save(self):
        return self.gui.save()
    
    def update_gui(self, interpreter_input): 
        self.gui.update_gui(interpreter_input)

class EventlineViewPluginGUI(QWidget):
            
    def __init__(self, parent):
        QWidget.__init__(self, parent)
        
        self.lastClicked = []     
        self._all_points = []           
        self.create_widgets(parent)
        self._lane_map = {}
        self._taken_lanes = {}
        self.map_points = {}
        
        self.known = []
        self.COLOR_ECU_AUTH = (255, 0, 0)
        self.COLOR_STR_AUTH = (0, 255, 0)
        self.COLOR_SIMPLE = (0, 0, 255)
        self.COLOR_PROCESS = (123, 123, 0)
        self.COLOR_PROCESS_2 = (0, 123, 123)
        
        self._init_categories()
        self._mode = 'LW_AUTH'
            
        self._pts_ecu = {} 
            
    def _already_there(self, mon_input): 
        ''' handles duplicates'''
        if hash(mon_input) in self.known: 
            return True      
        self.known.append(hash(mon_input))
        if len(self.known) > 1000:
            del self.known[:floor(float(len(self.known)) / 2.0)]
        return False
    
            
    def _clicked(self, plot, points):  
              
        for p in self.lastClicked:
            p.resetPen()
                    
        try: info = points[0].data()
        except: info = False
        
        if info:
            try: info[5]
            except: info += [0, 0, 0, 0, 0]
            
            if len(str(info[2])) > 100:
                showos = info[2][:99]
            else:
                showos = info[2]
            
            self.label.setText("ECU:  %s\t\t Time:%s \t\nMessageID:  %s \tMessage:  %s \t\nSize:  %s \t\t\tCorresponding ID:  %s \tStream ID:  %s" % (info[0], info[-1], self._id_to_str(info[1]), showos, info[3], info[6], info[5]))

        for p in points:
            p.setPen('b', width=2)
        self.lastClicked = points   
                
    def _init_categories(self):
        
        # TESLA
        self.tesla_time_sync_send = [MonitorTags.CP_SEND_SYNC_MESSAGE, MonitorTags.CP_SEND_SYNC_RESPONSE_MESSAGE]
        self.tesla_time_sync_rec = [MonitorTags.CP_RECEIVE_SYNC_RESPONSE_MESSAGE]
        
        self.tesla_setup_send = [MonitorTags.CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN]
        self.tesla_setup_rec = [MonitorTags.CP_RECEIVED_EXCHANGE_FIRST_KEY_KN]
        
        self.tesla_simple_message_send = [MonitorTags.CP_MACED_TRANSMIT_MESSAGE]
        self.tesla_simple_message_rec = [MonitorTags.CP_BUFFERED_SIMPLE_MESSAGE]
        
        self.tesla_message_authenticated = [MonitorTags.CP_RETURNED_AUTHENTICATED_SIMPLE_MESSAGE]
    
        self.tesla = self.tesla_time_sync_send + self.tesla_time_sync_rec + self.tesla_setup_send + self.tesla_setup_rec + self.tesla_simple_message_send + self.tesla_simple_message_rec + self.tesla_message_authenticated
        
        # TLS
        self.hand_shake_tag_server_send = [MonitorTags.CP_SEND_SERVER_HELLO, MonitorTags.CP_SEND_SERVER_CERTIFICATE, MonitorTags.CP_SEND_SERVER_KEYEXCHANGE, MonitorTags.CP_SEND_CERTIFICATE_REQUEST, MonitorTags.CP_SEND_SERVER_HELLO_DONE, \
                                           MonitorTags.CP_CLIENT_FINISHED_GENERATED_HASH_PRF]
        self.hand_shake_tag_server_rec = [MonitorTags.CP_RECEIVE_CLIENT_HELLO, MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE, MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE, MonitorTags.CP_RECEIVE_CERTIFICATE_VERIFY, MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC, \
                                          MonitorTags.CP_RECEIVE_CLIENT_FINISHED]
        self.hand_shake_tag_server_process = [MonitorTags.CP_CLIENT_CERTIFICATE_VALIDATED, MonitorTags.CP_DECRYPTED_CLIENT_KEYEXCHANGE, MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY , MonitorTags.CP_GENERATED_MASTER_SECRET_CERT_VERIFY, \
                                              MonitorTags.CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH , MonitorTags.CP_CLIENT_AUTHENTICATED]
                
        self.hand_shake_tag_client_send = [MonitorTags.CP_SEND_CLIENT_HELLO, MonitorTags.CP_SEND_CLIENT_CERTIFICATE , MonitorTags.CP_ENCRYPTED_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_SEND_CIPHER_SPEC , MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED, MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED]
        
        
        self.hand_shake_tag_client_rec = [MonitorTags.CP_RECEIVE_SERVER_HELLO, MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE , MonitorTags.CP_RECEIVE_SERVER_KEYEXCHANGE, \
                                          MonitorTags.CP_RECEIVE_CERTIFICATE_REQUEST, MonitorTags.CP_RECEIVE_SERVER_HELLO_DONE, MonitorTags.CP_RECEIVE_SERVER_FINISHED  ]
        
        self.hand_shake_tag_client_process = [MonitorTags.CP_SERVER_HELLO_DONE_VALIDATED_CERT, MonitorTags.CP_ENCRYPTED_CLIENT_KEYEXCHANGE , MonitorTags.CP_GENERATED_MASTERSEC_CLIENT_KEYEXCHANGE , MonitorTags.CP_INIT_SEND_CERTIFICATE_VERIFY, \
                                              MonitorTags.CP_ENCRYPTED_CERTIFICATE_VERIFY, MonitorTags.CP_INIT_CLIENT_FINISHED , MonitorTags.CP_HASHED_CLIENT_FINISHED, MonitorTags.CP_SERVER_FINISHED_HASHED_COMPARISON_HASH , \
                                              MonitorTags.CP_SERVER_FINISHED_GENERATED_HASH_PRF, MonitorTags.CP_INIT_SERVER_FINISHED , MonitorTags.CP_HASHED_SERVER_FINISHED, MonitorTags.CP_SERVER_AUTHENTICATED ]
        
        self.simple_tags_send = [MonitorTags.CP_SESSION_AVAILABLE_SEND_MESSAGE]
        self.simple_tags_rec = [ MonitorTags.CP_RECEIVE_SIMPLE_MESSAGE  ]
                
        self.tls = self.hand_shake_tag_server_send + self.hand_shake_tag_server_rec + self.hand_shake_tag_server_process + self.hand_shake_tag_client_send + self.hand_shake_tag_client_rec + self.hand_shake_tag_client_process \
                + self.simple_tags_send + self.simple_tags_rec 
                
        # authentication
        self.sec_mod_tags = [MonitorTags.CP_SEC_INIT_AUTHENTICATION, MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE, MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG, \
                             MonitorTags.CP_SEC_ENCRYPTED_DENY_MESSAGE, MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE, MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE, MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE]
            
        self.authent_tags_send = [MonitorTags.CP_SEC_INIT_AUTHENTICATION, MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE, MonitorTags.CP_ECU_SEND_REG_MESSAGE]
        self.authent_tags_receive = [MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG, MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE, MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE]
                            
        self.author_tags_send = [MonitorTags.CP_SEC_ENCRYPTED_DENY_MESSAGE, MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE, MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE]
        self.author_tags_receive = [MonitorTags.CP_ECU_DECRYPTED_DENY_MESSAGE, MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE, MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE]
        
        self.simp_tags_send = [MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE]
        self.simp_tags_receive = [MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE]
             
        self.lw_auth = self.sec_mod_tags + self.authent_tags_send + self.authent_tags_receive + self.author_tags_send + self.author_tags_receive + self.simp_tags_send + self.simp_tags_receive 
            
    def create_widgets(self, parent):
        vbox = QtGui.QVBoxLayout()        
        self.label = QtGui.QLabel()
        self.label.setText("Chainview")
        
        view = pg.GraphicsLayoutWidget(parent) 
        self.axis = ECUShowAxis(orientation='left')
        self.plot = view.addPlot(axisItems={'left': self.axis})

        self.plot.setLabel('left', 'ECU ID ')
        self.plot.setLabel('bottom', 'Time [sec]')
        self.plot.showGrid(x=True, y=True)
        
        
        
        vbox.addWidget(self.label)
        vbox.addWidget(view)
        self.setLayout(vbox)
    
    def save(self):
        return self._all_points
    
    def load(self, val_pairs):
        self._all_points = val_pairs
        spots = []
        for val in val_pairs:
            x_pos = val[0]
            y_pos = val[1]
            info = val[2:-2]
            arr = np.ndarray(2)
            arr[0] = x_pos
            arr[1] = y_pos
            spots.append({'pos': arr, 'data': info, 'brush':pg.mkBrush(val[-2][0], val[-2][1], val[-2][2], 120), 'symbol': val[-1], 'size': 8})
                                                
        s2 = pg.ScatterPlotItem(size=10, pen=pg.mkPen('w'), pxMode=True)            
        s2.addPoints(spots)
        self.plot.addItem(s2)
        s2.sigClicked.connect(self._clicked)
    
    def _next_security_module_lane(self, id_string):
        # determine next
        
        # if same element return coresponding
        if id_string in self._taken_lanes:
            return self._taken_lanes[id_string]
        
        try:
            num = -int(self._get_last_num(id_string))
        except:
            num = -1
        
        if num in self._taken_lanes.values():
            while True:
                num += 1
                if num in self._taken_lanes.values():
                    break
        self._taken_lanes[id_string] = num
        
        self.axis.lanes_map[num] = id_string

        return num
    
    def _next_ecu_lane(self, id_string):
        # determine next
        
        # if same element return coresponding
        if id_string in self._taken_lanes:
            return self._taken_lanes[id_string]
        
        try:
            num = int(self._get_last_num(id_string))
        except:
            num = None
        
        if num in self._taken_lanes.values() or num == None:
            if num == None: num = 0
            while True:
                num += 1
                if num not in self._taken_lanes.values():
                    break
        self._taken_lanes[id_string] = num
        self.axis.lanes_map[num] = id_string
        return num
    
    def update_gui(self, monitor_input_lst):

        val_pairs = []        

#         print("Eventmonitor start %s" % monitor_input_lst)
        for monitor_input in monitor_input_lst:
            
            if self._already_there(str(monitor_input)): continue
                        
            # get ecu ids
            if isinstance(monitor_input, str):
                for ecu_id in monitor_input_lst:
                    if not isinstance(ecu_id, str): continue
                    if isinstance(ecu_id, UUID): continue
                    self._next_ecu_lane(ecu_id)
                continue
            if not isinstance(monitor_input, (list, tuple)): continue
            
#             if self._already_there(monitor_input): continue
            
            # Define mode
            if eval(monitor_input[3]) in self.tesla:
                self._mode = "TESLA"
            if eval(monitor_input[3]) in self.tls:
                self._mode = "TLS"
            if eval(monitor_input[3]) in self.lw_auth:
                self._mode = "LW_AUTH"
            
            #  extract information 
            try: t = monitor_input[0]        
            except: continue                          
            
            
            # assign a lane to it
            if eval(monitor_input[3]) in self.sec_mod_tags:  # security module
                id_val = self._next_security_module_lane(monitor_input[1])                
            else:  # ecu
                id_val = self._next_ecu_lane(monitor_input[1])

                
            id_val += 0.00000001
                    
            # gather information
            fst = [t, id_val, monitor_input[1]]            
            try: scd = [monitor_input[4], monitor_input[5], monitor_input[6], monitor_input[1], monitor_input[7], monitor_input[2], monitor_input[0]] + [t]
            except: continue
            
            # Color
            color = (0, 0, 0)
            symb = 0          
            if eval(monitor_input[3]) in self.authent_tags_send + self.hand_shake_tag_client_send + self.tesla_time_sync_send:
                color = self.COLOR_ECU_AUTH
                symb = 0                    
            if eval(monitor_input[3]) in self.authent_tags_receive + self.hand_shake_tag_client_rec + self.tesla_time_sync_rec:
                color = self.COLOR_ECU_AUTH
                symb = 1
            if eval(monitor_input[3]) in self.author_tags_send + self.hand_shake_tag_server_send + self.tesla_setup_send:
                color = self.COLOR_STR_AUTH
                symb = 0
            if eval(monitor_input[3]) in self.author_tags_receive + self.hand_shake_tag_server_rec + self.tesla_setup_rec:
                color = self.COLOR_STR_AUTH
                symb = 1
            if eval(monitor_input[3]) in self.simp_tags_send + self.simple_tags_send + self.tesla_simple_message_send:
                color = self.COLOR_SIMPLE
                symb = 0
            if eval(monitor_input[3]) in self.simp_tags_receive + self.simple_tags_rec + self.tesla_simple_message_rec:
                color = self.COLOR_SIMPLE
                symb = 1        
            if eval(monitor_input[3]) in self.tesla_message_authenticated:
                color = self.COLOR_PROCESS_2
                symb = 2
#             if eval(monitor_input[3]) in self.hand_shake_tag_server_process:
#                 color = self.COLOR_STR_AUTH
#                 symb = 2        
            if color == (0, 0, 0): continue                
            
            # value pair         
            val_pairs.append(fst + scd + [color, symb])
        
        spots = []
        try: last_free = val_pairs[0][0]
        except: last_free = None
        for val in val_pairs:
            x_pos = val[0]
            y_pos = val[1]
            info = val[2:-2]
            try: info[2] = info[2].get()
            except: pass
            
            
            # Points at same y positions will be shifted to be distinguishable
            res = False
                        
            try: already_existing = self._pts_ecu[info[0]][x_pos]
            except: already_existing = False
            if already_existing: 
#                 x_pos = last_free
                # find new value
                found = False
                while not found:
                    x_pos += 0.00001
                    try: already_existing = self._pts_ecu[info[0]][x_pos]
                    except: already_existing = False
                    if not already_existing:
                        found = True
#                         last_free = x_pos
            # print("    Plotting x: %s" % x_pos)
            General().add_to_three_dict(self._pts_ecu, info[0], x_pos, True)
            
            arr = np.ndarray(2)
            arr[0] = x_pos
            arr[1] = y_pos
            spots.append({'pos': arr, 'data': info, 'brush':pg.mkBrush(val[-2][0], val[-2][1], val[-2][2], 120), 'symbol': val[-1], 'size': 8})
                                                
        s2 = pg.ScatterPlotItem(size=10, pen=pg.mkPen('w'), pxMode=True)            
        s2.addPoints(spots)
        self.plot.addItem(s2)
        s2.sigClicked.connect(self._clicked)
        
        
        self._all_points += val_pairs
        
#         self.map_points[str(s2[0])]   
#         print("Eventmonitor end")
                    
    def _get_last_num(self, stri):
        num = ""
        for el in stri[::-1]:
            if isnumeric(el):
                num += el
            else:
                break
        return num[::-1]
                    
    def _id_to_str(self, msg_id):
        
        if self._mode == "TLS":
            if msg_id == can_registration.CAN_TLS_CERTIFICATE:
                return "Client Certificate"
            if msg_id == can_registration.CAN_TLS_CERTIFICATE_REQUEST:
                return "Certificate Request"
            if msg_id == can_registration.CAN_TLS_CERTIFICATE_VERIFY:
                return "Certificate Verify"
            if msg_id == can_registration.CAN_TLS_CHANGE_CIPHER_SPEC:
                return "Change Cipher Spec"
            if msg_id == can_registration.CAN_TLS_CLIENT_HELLO:
                return "ClientHello"
            if msg_id == can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE:
                return "Client Key Exchange"
            if msg_id == can_registration.CAN_TLS_FINISHED:
                return "Finished "
            
            if msg_id == can_registration.CAN_TLS_SERVER_CERTIFICATE:
                return "Server Certificate "
            if msg_id == can_registration.CAN_TLS_SERVER_HELLO:
                return "ServerHello "
            if msg_id == can_registration.CAN_TLS_SERVER_HELLO_DONE:
                return "ServerHelloDone "
            
            if msg_id == can_registration.CAN_TLS_SERVER_KEY_EXCHANGE:
                return "ServerKeyExchange "           
        
        if self._mode == "LW_AUTH":
            if msg_id == can_registration.CAN_ECU_AUTH_ADVERTISE:
                return "ECU Advertisement"
            if msg_id == can_registration.CAN_ECU_AUTH_CONF_MSG:
                return "Confirmation Message"
            if msg_id == can_registration.CAN_ECU_AUTH_REG_MSG:
                return "Registration Message"
            if msg_id == can_registration.CAN_STR_AUTH_DENY_MSG:
                return "Deny Message"
            if msg_id == can_registration.CAN_STR_AUTH_GRANT_MSG:
                return "Grant Message"
            if msg_id == can_registration.CAN_STR_AUTH_INIT_MSG_STR:
                return "Request Message"
        
        if self._mode == "TESLA":
            if msg_id == can_registration.CAN_TESLA_TIME_SYNC:
                return "Time Sync"
            if msg_id == can_registration.CAN_TESLA_TIME_SYNC_RESPONSE:
                return "Time Sync Response"
            if msg_id == can_registration.CAN_TESLA_KEY_EXCHANGE:
                return "Key Exchange"
        
        return msg_id

    def _is_sec_mod(self, ecu):
        try:   
            ecu._SECMODULE
            return True              
        except:
            pass
        return False

        

        
