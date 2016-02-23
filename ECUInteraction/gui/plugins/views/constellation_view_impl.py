'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''
from gui.plugins.views.abstract_viewer_plug import AbstractViewerPlugin
from PyQt4.Qt import QWidget
from PyQt4 import QtGui, QtCore
from io_processing.surveillance_handler import MonitorTags
from pyqtgraph.flowchart.Flowchart import Flowchart
from io_processing.result_interpreter.constellation_interpreter import ConstellationInterpreter
from math import sqrt
from tools.general import General
import math
import traceback
from uuid import UUID
from gui.gui_builder import GBuilder
from PyQt4.QtGui import QTableWidgetItem, QAbstractItemView
from pyqtgraph.flowchart.Node import Node
from api.core.api_core import APICore
import copy


class ConstellationViewPlugin(AbstractViewerPlugin):

    def __init__(self, *args, **kwargs):
        AbstractViewerPlugin.__init__(self, *args, **kwargs)
                
    def get_combobox_name(self):
        return "Constellation"

    def get_widget(self, parent):
        self.gui = ConstellationViewPluginGUI(parent)
        return self.gui
    
    def get_interpreters(self):
        return [ConstellationInterpreter]
    
    def load(self, data):
        self.gui.load(data)
    
    def save(self):
        return self.gui.save()
    
    def update_gui(self, interpreter_input): 
        self.gui.update_gui(interpreter_input)

class ConstellationViewPluginGUI(QWidget):
            
    def __init__(self, parent):
        QWidget.__init__(self, parent)
        
        self._radius = 350
        self._gw_distance = 2 * self._radius
        self._bus_distance = 4 * self._radius
        self._last_bus_pos = [0, 0]
        self._last_bus_steps = [0, 0]
        self._bus_node = {}
        self._bus_position = {}
        
        self._ecu_terminals = {}
        self._ecu_position = {}
        self._ecu_node = {}
        
        self._show_dict = {}
        
        
        self.lastClicked = []     
        self._all_points = []           
        self.create_widgets(parent)
        
        
        self.map_points = {}
        
        self.COLOR_ECU_AUTH = (255, 0, 0)
        self.COLOR_STR_AUTH = (0, 255, 0)
        self.COLOR_SIMPLE = (0, 0, 255)
        self.COLOR_PROCESS = (123, 123, 0)
        self.COLOR_PROCESS_2 = (0, 123, 123)
        
        self._init_categories()
        self._mode = 'LW_AUTH'
            
        self._pts_ecu = {} 
            
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
        self.hand_shake_tag_server_rec = [MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE, MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE, MonitorTags.CP_RECEIVE_CERTIFICATE_VERIFY, MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC, \
                                          MonitorTags.CP_RECEIVE_CLIENT_FINISHED]
        self.hand_shake_tag_server_process = [MonitorTags.CP_CLIENT_CERTIFICATE_VALIDATED, MonitorTags.CP_DECRYPTED_CLIENT_KEYEXCHANGE, MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY , MonitorTags.CP_GENERATED_MASTER_SECRET_CERT_VERIFY, \
                                              MonitorTags.CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH , MonitorTags.CP_CLIENT_AUTHENTICATED]
                
        self.hand_shake_tag_client_send = [MonitorTags.CP_SEND_CLIENT_HELLO, MonitorTags.CP_SEND_CLIENT_CERTIFICATE , MonitorTags.CP_INIT_SEND_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_SEND_CIPHER_SPEC , MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED, MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED]
        
        
        self.hand_shake_tag_client_rec = [MonitorTags.CP_RECEIVE_CLIENT_HELLO, MonitorTags.CP_RECEIVE_SERVER_HELLO, MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE , MonitorTags.CP_RECEIVE_SERVER_KEYEXCHANGE, \
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
        self.label.setText("Constellation")
        self.label.setFixedHeight(20)
        
        self.fc = Flowchart(terminals={'Connection': {'io': 'in'}})        
        self.fc._nodes['Input'].close()
        self.fc._nodes['Output'].close()

        self.view = self.fc.widget()
        wig = self.view.chartWidget
        self.view.chartWidget.hoverDock.hide()
        self.view.chartWidget.selectedTree.hide()        
        self.view.chartWidget.selDock.label.setText("Selected Comp.")
        
        # add selection label
        self.selection_label = self.view.chartWidget.selDescLabel
        self.selection_label.setText("")
        self.selection_label.setFixedHeight(15)
        
        # add information table
        self.info_table = GBuilder().table(self.view.chartWidget.selDock, 1, 2, ["Settings", "Value"])
        for r in range(self.info_table.rowCount()):
            self.info_table.setRowHeight(r, 20)
        self.info_table.horizontalHeader().hide()
        self.info_table.verticalHeader().hide()
        self.info_table.setSelectionBehavior(QAbstractItemView.SelectRows); 
        self.info_table.setSortingEnabled(True)
#         self.view.chartWidget.selInfoLayout.addWidget(self.selection_label)
        self.view.chartWidget.selInfoLayout.addWidget(self.info_table)
        
        # override on selection
        self.view.chartWidget._scene.selectionChanged.connect(self._selection_changed)
        
        vbox.addWidget(self.label)
        vbox.addWidget(wig)
        self.setLayout(vbox)
    
    def save(self):
        
        data = {}
        
        bus_ecu_connections = self.bus_ecu_connections  # pur so uebernehmen
        bus_data = self._get_save_bus()
        ecu_data = self._get_save_ecu()
                
        data['bus_data'] = bus_data
        data['ecu_data'] = ecu_data
        data['ecu_positions'] = self._ecu_position
        data['bus_positions'] = self._bus_position
        data['bus_ecu_connections'] = bus_ecu_connections

        print("SSVR I")
        return data
    
    def load(self, data):
        
        self._ecu_position = data['ecu_positions']
        self._bus_position = data['bus_positions']
        bus_data = data['bus_data']
        ecu_data = data['ecu_data']
        bus_ecu_connections = data['bus_ecu_connections']
        
        # add busses
        self._add_buses_load(bus_data)
    
        # add ecus
        self._add_ecus_load(ecu_data, bus_ecu_connections)
         
    def update_gui(self, monitor_input_list):
        ''' this method is called exactly once and should show all 
            information
        '''
        
        # extract information
        try: constellation = monitor_input_list[0].data
        except: return
        ecu_groups = constellation[0]
        bus_groups = constellation[1]        
        bus_ecu_connections = constellation[2]
        self.bus_ecu_connections = bus_ecu_connections
        
        # set cans
        self._add_buses(bus_groups)
        
        # add ecus
        self._add_ecus(ecu_groups, bus_ecu_connections)
             
    
    def _selection_changed(self):
        
        items = self.view.chartWidget._scene.selectedItems()

        if len(items) == 0:
            data = None
        else:
            item = items[0]

            if hasattr(item, 'node') and isinstance(item.node, Node):
                print(item.node)
                print("SELECTED %s" % item.node.settings_dict)
                self._show_node_information(item.node)

            else:
                data = None
        
#         self.selectedTree.setData(data, hideRoot=True)
    
    def _show_node_information(self, node):
        
        # hide all rows
        for r in range(self.info_table.rowCount()):
            self.info_table.setRowHidden(r, True)
        
        # add new information save dict[ecu_id][settings_id] = row_nr
        comp_id = node.settings_dict['comp_id']      
        self.selection_label.setText("Selected ECU:      %s" % comp_id)

        for set_key in node.settings_dict.keys():
            
            # if already exists -> show its row and skip
            try: 
                row_nr = self._show_dict[comp_id][set_key]
                self.info_table.setRowHidden(row_nr, False)
                continue
            except: pass
                        
            # else add it to table and show row
            self.info_table.setRowCount(self.info_table.rowCount() + 1)
            row_nr = self.info_table.rowCount()          
            item_1 = QTableWidgetItem()
            item_1.setData(QtCore.Qt.EditRole, set_key)  
            item_2 = QTableWidgetItem()
            item_2.setText(str(node.settings_dict[set_key]));  
            General().add_to_three_dict(self._show_dict, comp_id, set_key, row_nr)            
            self.info_table.setItem(row_nr - 1, 0, item_1)
            self.info_table.setItem(row_nr - 1, 1, item_2)
            self.info_table.setRowHeight(row_nr - 1, 20)
    
    def _get_save_bus(self):
        
        buses = []
        for bus_id in self._bus_node:
            node = self._bus_node[bus_id]
            settings = node.get_string_settings()
            
            buses.append([bus_id, settings])
        return buses
       
    def _add_buses_load(self, bus_data):
        
        nr_buses = len(bus_data)        
      
        
        for b_group in bus_data:
            bus_id = b_group[0]
            bus_settings = b_group[1]
             
            # place the busses
            [x, y] = self._bus_position[bus_id]
            
            node = InformationNode(bus_id)
            node.settings_dict = bus_settings
            self._bus_node[bus_id] = node
            self.fc.addNode(node, bus_id, [x, y])         
            self._bus_position[bus_id] = [x, y]
            
    def _add_buses(self, bus_groups):
        first = True
        nr_buses = len(bus_groups)
        
        for b_group in bus_groups:
            bus = b_group[0]
                         
            # place the busses
            if not first: [x, y] = self._next_bus_pos(nr_buses)
            else: [x, y] = [0, 0]
            first = False
            node = InformationNode(bus.comp_id)
            node.set_settings(bus)
            self._bus_node[bus.comp_id] = node
            self.fc.addNode(node, bus.comp_id, [x, y])         
            self._bus_position[bus.comp_id] = [x, y]

    def _get_save_ecu(self):
        ecus = []
        for ecu_id in self._ecu_node:
            node = self._ecu_node[ecu_id]
            settings = node.get_string_settings()
            ecus.append([ecu_id, settings])
        return ecus
        
    def _add_ecus_load(self, ecu_data, bus_ecu_connections):
        ''' add all ecus to the respective buses '''
        ecu_dict = self._can_ecu_list_dictionary(bus_ecu_connections)        
        
        for bus_id in ecu_dict:
            idx = 0    
            ecu_list = ecu_dict[bus_id]
            for ecu_id in ecu_list:
                if isinstance(ecu_id, UUID): ecu_id = "GW\n%s" % str(ecu_id.hex)
                
                ecu_dat = self._ecu_dat_from_id(ecu_id, ecu_data)
                
                ecu_id = ecu_dat[0]
                ecu_settings = ecu_dat[1]
                
                [x, y] = self._ecu_position[ecu_id]
                
                ecu_id_show = ecu_id
                                    
                # shorten name if to long
                if len(ecu_id) >= 13:
                    ecu_id_show = ecu_id[:13]
                    
                # calculate positions       
                idx += 1         
                try:
                    # if this already exists gets a second connection
                    ecu_terminal = False
                    if ecu_id in self._ecu_node.keys():
                        ecu_terminal = self._ecu_node[ecu_id].addInput('C%s' % idx)                                                
                        
                    # create new node
                    if not ecu_terminal:
                        node = InformationNode(ecu_id_show)
                        # set information
                        node.settings_dict = ecu_settings
                        self.fc.addNode(node, ecu_id_show, [x, y])         
                        self._ecu_position[ecu_id] = [x, y]
                        self._ecu_node[ecu_id] = node
                        ecu_terminal = node.addInput('C%s' % idx)
                    
                    bus_terminal = self._bus_node[bus_id].addInput('C%s' % idx)
                except:
                    traceback.print_exc()
                
                # connector to bus
                try:
                    self.fc.connectTerminals(bus_terminal, ecu_terminal)
                except:
                    pass

    def _add_ecus(self, ecu_groups, bus_ecu_connections):
        ''' add all ecus to the respective buses '''
        ecu_dict = self._can_ecu_list_dictionary(bus_ecu_connections)        
        
        for bus_id in ecu_dict:
            ecu_list = ecu_dict[bus_id]
            nr_ecus = len(ecu_list)
            pos_bus = self._bus_position[bus_id]
            idx = 0
            
            if bus_id == "CAN0":
                a = 0
            for ecu_id in ecu_list:
                ecu_id_show = ecu_id
                ecu = self._ecu_from_group(ecu_groups, ecu_id)
                
                [x, y] = self._next_ecu_pos(pos_bus, nr_ecus, idx)
                
                if isinstance(ecu_id, UUID):
                    ecu_id = "GW\n%s" % ecu_id.hex                    
                    [x, y] = self._get_gw_position(ecu)
                    
                # shorten name if to long
                if len(ecu_id) >= 13:
                    ecu_id_show = ecu_id[:13]
                    
                # calculate positions
                idx += 1
                try:
                    # if this already exists gets a second connection
                    ecu_terminal = False
                    if ecu_id in self._ecu_node.keys():
                        ecu_terminal = self._ecu_node[ecu_id].addInput('C%s' % idx)                                                
                        
                    # create new node
                    if not ecu_terminal:
                        node = InformationNode(ecu_id_show)
                        # set information
                        node.set_settings(ecu)
                        self.fc.addNode(node, ecu_id_show, [x, y])         
                        self._ecu_position[ecu_id] = [x, y]
                        self._ecu_node[ecu_id] = node
                        ecu_terminal = node.addInput('C%s' % idx)
                    
                    bus_terminal = self._bus_node[bus_id].addInput('C%s' % idx)
                except:
                    traceback.print_exc()
                
                # connector to bus
                try:
                    self.fc.connectTerminals(bus_terminal, ecu_terminal)
                except:
                    pass
    
    def _ecu_dat_from_id(self, ecu_id, ecu_data):    
        
        for ecu_dat in ecu_data:
            if ecu_dat[0] == ecu_id:
                return ecu_dat
        return None
            
    def _ecu_from_group(self, ecu_groups, ecu_id):
        for ecu_lists in ecu_groups:
            ecu_list = ecu_lists[0]
            ecu_spec = ecu_lists[1]
            for ecu in ecu_list:
                if ecu.ecu_id == ecu_id:
                    return ecu
        return None
            
    def _get_gw_position(self, gateway):
        x_points = []
        y_points = []
        
        for bus in gateway.connected_bus:            
            x_points.append(self._bus_position[bus.comp_id][0])
            y_points.append(self._bus_position[bus.comp_id][1])        
            
        x = float(sum(x_points)) / float(len(x_points))
        y = float(sum(y_points)) / float(len(y_points))
        
        for bus in gateway.connected_bus:    
            if self._bus_position[bus.comp_id][0] == x and self._bus_position[bus.comp_id][1] == y:
                y += self._gw_distance
        
        return [x, y]
        
                
    def _can_ecu_list_dictionary(self, bus_ecu_connections):
        ''' creates a dictinary of form key: bus id and
            value list of ecu ids connected to the bus
        
            Input:     bus_ecu_connections     list
            Output:    ecu_dict                dictionary
        '''
        out_dict = {}
        for connection in bus_ecu_connections:
            
            General().force_add_dict_list(out_dict, connection[0], connection[1])
            
        return out_dict
    
    def _next_ecu_pos(self, pos_bus, nr_ecus, idx):
        ''' determines the next position of the ecu'''
        
        
        alpha = (360 / nr_ecus) * 1.00000001
        angle = idx * alpha
        # radius varies with the number of ECUs connected (less means closer)
        radius = (math.sqrt(2) * 190) / (2 * math.sin(2 * math.pi * (alpha / 360)))  
        
        angle /= 360
        angle *= 2 * math.pi
        
        x = radius * math.cos(angle) + pos_bus[0]
        y = radius * math.sin(angle) + pos_bus[1]
                   
        return [x, y]
    
    def _next_bus_pos(self, nr_buses):
        ''' determines the next position of the bus'''
        
        if nr_buses < 5:
            [x, y] = self._last_bus_pos      
            [lr, ud] = self._last_bus_steps
            x += self._bus_distance
            self._last_bus_pos[0] = x
            return [x, y]
        
        [x, y] = self._last_bus_pos      
        [lr, ud] = self._last_bus_steps
        step = round(sqrt(nr_buses / 3))
        
        y += self._bus_distance
        
        if ud == step:
            y = 0
            ud = 0
            x += self._bus_distance
            self._last_bus_steps = [lr + 1, 0]       
            lr += 1
        ud += 1
        self._last_bus_steps = [lr, ud]
        self._last_bus_pos = [x, y]
        return [x, y]
                    
    def _is_sec_mod(self, ecu):
        try:   
            ecu._SECMODULE
            return True              
        except:
            pass
        return False

class InformationNode(Node):
    
    def __init__(self, name, terminals=None, allowAddInput=False, allowAddOutput=False, allowRemove=True):
        Node.__init__(self, name, terminals, allowAddInput, allowAddOutput, allowRemove)
    
        self.settings_dict = {}
            
    def set_settings(self, component):        
        self.settings_dict = self._extract_settings(component)
        
    def _extract_settings(self, component):
        
        settings_dict = {}
        
        settings_dict['comp_id'] = str(APICore()._id_from_component(component))
        
        try: settings_dict['jitter'] = str(component._jitter)
        except: pass
        
        try: settings_dict['set authenticated'] = str(component._authenticated)
        except: pass
        
        try: settings_dict['buffer size: receive '] = str(component.ecuHW.controller.max_receive_size)
        except: pass
        
        try: settings_dict['buffer size: transmit'] = str(component.ecuHW.controller.max_transmit_size)
        except: pass
        
        try: settings_dict['HW: transceiver'] = str(component.ecuHW.transceiver.__class__.__name__)
        except: pass
        
        try: settings_dict['HW: controller'] = str(component.ecuHW.controller.__class__.__name__)
        except: pass
        
        try: settings_dict['HW: microcontroller'] = str(component.ecuHW.mic_controller.__class__.__name__)
        except: pass
        
        try: settings_dict['layer: communication module'] = str(component.ecuSW.comm_mod.__class__.__name__)
        except: pass
        
        try: settings_dict['layer: application'] = str(component.ecuSW.app_lay.__class__.__name__)
        except: pass
        
        try: settings_dict['layer: transport'] = str(component.ecuSW.comm_mod.transp_lay.__class__.__name__)
        except: pass
        
        try: settings_dict['layer: data link'] = str(component.ecuSW.comm_mod.datalink_lay.__class__.__name__)
        except: pass
        
        try: settings_dict['layer: physical'] = str(component.ecuSW.comm_mod.physical_lay.__class__.__name__)
        except: pass
        
        for set_key in component.settings:
            set_value = APICore()._get_setting_val(component, set_key)            
            settings_dict[set_key] = str(set_value)
            
        return settings_dict
            
    def get_string_settings(self):
        ''' this method returns a saveable list of settings from the generated settings 
            dictionary of the object'''
        return copy.deepcopy(self.settings_dict)
