'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''
import pyqtgraph as pg
from gui.plugins.views.abstract_viewer_plug import AbstractViewerPlugin
from PyQt4 import QtGui, QtCore
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter
from math import floor
from gui.gui_builder import GBuilder
from pyqtgraph import dockarea
from PyQt4.QtGui import QSpacerItem, QHBoxLayout, QColor
from tools.ecu_logging import ECULogger, try_ex
from io_processing.result_interpreter.constellation_interpreter import ConstellationInterpreter
from api.core.api_core import APICore
from io_processing.surveillance_handler import MonitorTags
from tools.general import General
from config import can_registration

class MessageCountViewPlugin(AbstractViewerPlugin):

    def __init__(self, *args, **kwargs):
        AbstractViewerPlugin.__init__(self, *args, **kwargs)
        
    def get_combobox_name(self):
        return "Message Count"

    def get_widget(self, parent):
        self.gui = MessageCountViewPluginGUI(parent)
        return self.gui
    
    def get_interpreters(self):
        return [EventlineInterpreter, ConstellationInterpreter]

    def load(self, data):
        self.gui.load(data)
    
    def save(self):
        return self.gui.save()
    
    def update_gui(self, interpreter_input): 
        self.gui.update_gui(interpreter_input)

class MessageCountViewPluginGUI(dockarea.DockArea):
            
    def __init__(self, parent):
        dockarea.DockArea.__init__(self)
                   
        self.builder = GBuilder()  
        self._bin = {}
        
        self.widget_index = {} 
        self.widget_text = {}
        self.send_plot_text = {}
        self.rec_plot_text = {}
        self.dock_index = {}
        
        self._ecu_ids = []
        self._information_box_items = ["a"]
        self._info_widget_index = {}
        
        self._init_tag_list()
        
        self.known = []      
        
        self.create_widgets(parent)              
            
#     def _already_there(self, mon_input): 
#         ''' handles duplicates'''
#         if hash(mon_input) in self.known: 
#             return True      
#         self.known.append(hash(mon_input))
#         if len(self.known) > 1000:
#             del self.known[:floor(float(len(self.known)) / 2.0)]
#         return False
            
    def create_widgets(self, parent):
        h_layout = QHBoxLayout()
        self.viewer_cbox = self.builder.checkable_combobox(parent, [], self._set_cb_changed)

        h_layout.addWidget(self.viewer_cbox)
        h_layout.addItem(QSpacerItem(10, 10))
        
        # add ecu selection
        self.label_top = QtGui.QLabel()
        self.label_top.setText("Message View:    green: received messages       red: send message")
        self.viewDock = dockarea.Dock('view', size=(1000, 600))
        self.layout.addWidget(self.label_top)
        self.label_top.setFixedHeight(20)
        self.layout.addLayout(h_layout)        
        self.layout.addItem(QSpacerItem(10, 10))
    
    def _add_items_ecu_ids(self, ecu_ids):
        items = []
        for ecu_id in ecu_ids:
            try: items += [self.add_item(ecu_id)]
            except: pass
        
        if not items: return
        
        for i in items:
            i.setCheckState(QtCore.Qt.Unchecked)
        items[0].setCheckState(QtCore.Qt.Checked) 
        self._set_cb_changed(None)
    
    def _set_cb_changed(self, e):
        
        # clear all
        try:
            for ky in self.dock_index:
                self.dock_index[ky].setParent(None)    
        except:
            ECULogger().log_traceback()
        
        # get checked items
        checked_idx = []
        for cnt in range(self.viewer_cbox.count()):
            item = self.viewer_cbox.model().item(cnt, 0)
            if item.checkState():                
                checked_idx.append(cnt)
        
        for ky in range(self.viewer_cbox.count()):
            
            # selected draw
            if ky in checked_idx:
                self.addDock(self.dock_index[ky], 'right')                   
                self.widget_index[ky].verticalScrollBar().setValue(self.widget_index[ky].verticalScrollBar().maximum());
      
    def add_item(self, title_text):
        
        # add item to dock      
        new_dock = dockarea.Dock(title_text, size=(1000, 20))
        new_dock.setOrientation('horizontal')
        widget, send_plot = self._new_plot_widget(new_dock)   
        new_dock.addWidget(widget)
        
        self.addDock(new_dock, 'right')
        
        # add item to combobox
        self.viewer_cbox.addItem(title_text)        
        new_row = self.viewer_cbox.count() - 1
        item = self.viewer_cbox.model().item(new_row, 0)
        item.setCheckState(QtCore.Qt.Checked)
        
        
        # link items
        self.widget_index[new_row] = widget
        self.widget_text[title_text] = widget
        self.send_plot_text[title_text] = send_plot
        self.dock_index[new_row] = new_dock
        
        return item
    
    def _new_plot_widget(self, parent):
        
        widget = pg.GraphicsLayoutWidget(parent) 
#         self.axis = ECUShowAxis(orientation='left')
        send_plot = widget.addPlot()  # axisItems={'left': self.axis})
        
        send_plot.setLabel('left', 'Number of messages')
        send_plot.setLabel('bottom', 'Message ID')
        send_plot.showGrid(x=True, y=True) 
        
        x = []
        y = []
        try:
            barGraphItem = pg.BarGraphItem(x=x, height=y, width=0.5)
            send_plot.addItem(barGraphItem)
        except:
            ECULogger().log_traceback()
#         send_plot.plot(x, y, stepMode=True, fillLevel=0, brush=(0, 0, 255, 150))
#         rec_plot.plot(x, y, stepMode=True, fillLevel=0, brush=(255, 0, 0, 150))
        
        return widget, barGraphItem
    
    def save(self): 
        
        data = {}
        
        data["ecu ids"] = self._ecu_ids
        data["bin"] = self._bin
               
        return data
    
    def load(self, data):

        self._ecu_ids = data["ecu ids"]
        self._bin = data["bin"]
        self._add_items_ecu_ids(self._ecu_ids)   
        
        self._plot_bin()
    

    def _init_tag_list(self):
        
        # NO TESLA TAGS HERE YET!
        self._sent_tags = [MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE, MonitorTags.CP_SEC_INIT_AUTHENTICATION,
                          MonitorTags.CP_SEC_ENCRYPTED_DENY_MESSAGE, MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE,
                          MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE, MonitorTags.CP_ECU_SEND_REG_MESSAGE,
                          MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE, MonitorTags.CP_SEND_CLIENT_HELLO,
                          MonitorTags.CP_SEND_SERVER_HELLO, MonitorTags.CP_SEND_SERVER_CERTIFICATE,
                          MonitorTags.CP_SEND_SERVER_KEYEXCHANGE, MonitorTags.CP_SEND_CERTIFICATE_REQUEST,
                          MonitorTags.CP_SEND_SERVER_HELLO_DONE, MonitorTags.CP_SEND_CLIENT_CERTIFICATE,
                          MonitorTags.CP_ENCRYPTED_CERTIFICATE_VERIFY, MonitorTags.CP_SEND_CIPHER_SPEC,
                          MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED, MonitorTags.CP_SESSION_AVAILABLE_SEND_MESSAGE,
                          MonitorTags.CP_SETUP_FINISHED_CREATE_KEYS, MonitorTags.CP_INIT_TRANSMIT_MESSAGE,
                          MonitorTags.CP_SEND_SYNC_MESSAGE, MonitorTags.CP_SEND_SYNC_RESPONSE_MESSAGE,
                          MonitorTags.CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN]
        
        self._received_tags = [MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE, MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE,
                              MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE, MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT,
                              MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE, MonitorTags.CP_ECU_RECEIVE_DENY_MESSAGE,
                              MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE, MonitorTags.CP_RECEIVE_CLIENT_HELLO,
                              MonitorTags.CP_RECEIVE_SERVER_HELLO, MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE,
                              MonitorTags.CP_RECEIVE_SERVER_KEYEXCHANGE, MonitorTags.CP_RECEIVE_CERTIFICATE_REQUEST,
                              MonitorTags.CP_RECEIVE_SERVER_HELLO_DONE, MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE,
                              MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE, MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY,
                              MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC, MonitorTags.CP_RECEIVE_CLIENT_FINISHED,
                              MonitorTags.CP_RECEIVE_SERVER_FINISHED, MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED,
                              MonitorTags.CP_RECEIVE_SIMPLE_MESSAGE, MonitorTags.CP_RECEIVED_SIMPLE_MESSAGE,
                              MonitorTags.CP_RECEIVED_EXCHANGE_FIRST_KEY_KN, MonitorTags.CP_RECEIVE_SYNC_RESPONSE_MESSAGE,
                              MonitorTags.CP_RECEIVE_SYNC_MESSAGE]
    @try_ex
    def update_gui(self, monitor_input_list):

        
        # receive the ecu ids: show only the once selected then
        try: 
            if isinstance(monitor_input_list[0], str): return
            
            constellation = monitor_input_list[0].data
            ecu_groups = constellation[0]
            self._ecu_ids = [e.ecu_id for e in APICore()._ecu_list_from_groups(ecu_groups)]
            
            self._add_items_ecu_ids(self._ecu_ids)   
            return         
        except: 
            pass
        try:
            monitor_input_list.sort(key=lambda x: x[0], reverse=False)
        except:
            pass
            
        # receive simple inputs
        for monitor_input in monitor_input_list:
#             if self._already_there(monitor_input): continue

            # read information
            ecu_id = monitor_input[1]
            tag = eval(monitor_input[3])            
            message_id = monitor_input[4]
            stream_id = message_id  # monitor_input[7]
            
            if stream_id in [-1, 0]: 
                continue      
            
            
            if tag in self._sent_tags: 
                add_tag = 'sender'
            elif tag in self._received_tags: 
                add_tag = 'receiver'
            else: 
                continue
            
            if not General().four_dict_exists(self._bin, ecu_id, stream_id, add_tag):
                General().add_to_four_dict(self._bin, ecu_id, stream_id, add_tag, 1)
            else:
                self._bin[ecu_id][stream_id][add_tag] += 1
                
                
            # workaround tesla
            if tag == MonitorTags.CP_SEND_SYNC_RESPONSE_MESSAGE:
                if not General().four_dict_exists(self._bin, ecu_id, can_registration.CAN_TESLA_TIME_SYNC, "receiver"):
                    General().add_to_four_dict(self._bin, ecu_id, can_registration.CAN_TESLA_TIME_SYNC, "receiver", 1)
                else:
                    self._bin[ecu_id][can_registration.CAN_TESLA_TIME_SYNC]["receiver"] += 1
            
            
        # show updated
        self._plot_bin()
            
    def _plot_bin(self):
        
        
        # collect information        
        for ecu_id in self._bin.keys():
            x_values_send = []
            y_values_send = []
            color = []
            for stream_id in self._bin[ecu_id].keys():
                if stream_id == -1: continue
                
                # sender or receiver color?
                add_tag = list(self._bin[ecu_id][stream_id].keys())[0]
                x_values_send += [stream_id]
                y_values_send += [self._bin[ecu_id][stream_id][add_tag]]
                if add_tag == 'sender':     
                    color += [QColor(255, 0, 0)]
                elif add_tag == 'receiver':
                    color += [QColor(0, 255, 0)]
                else: continue    
            try:
                # send
                self.send_plot_text[ecu_id].setOpts(x=x_values_send, height=y_values_send, width=0.5, brushes=color)
            except KeyError: pass
            except:
                ECULogger().log_traceback()
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
                        
               

        

        
