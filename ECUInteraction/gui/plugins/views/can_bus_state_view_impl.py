'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''
from gui.plugins.views.abstract_viewer_plug import AbstractViewerPlugin
from PyQt4.Qt import QWidget, QRectF
from PyQt4 import QtGui, QtCore
import pyqtgraph as pg
import numpy as np
from numpy.core.defchararray import isnumeric
from config import can_registration
from io_processing.surveillance_handler import MonitorInput, MonitorTags
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter
from PyQt4.QtGui import QPainterPath, QColor
from io_processing.result_interpreter.can_bus_interpreter import CanBusInterpreter
from math import floor

class CanBusStateViewPlugin(AbstractViewerPlugin):

    def __init__(self, *args, **kwargs):
        AbstractViewerPlugin.__init__(self, *args, **kwargs)
                
    def get_combobox_name(self):
        return "Can Bus States"

    def get_widget(self, parent):
        self.gui = CanBusStateViewPluginGUI(parent)
        return self.gui
    
    def get_interpreters(self):
        return [CanBusInterpreter]
        
    def link_axis(self):
        return self.gui.plot
        
    def load(self, data):
        self.gui.load(data)
    
    def save(self):
        return self.gui.save()
    
    def update_gui(self, interpreter_input): 
        self.gui.update_gui(interpreter_input)

class CanBusStateViewPluginGUI(QWidget):
            
    def __init__(self, parent):
        QWidget.__init__(self, parent)
        
        self.known = []
        self._sender_to_track = {}
        self._track_cnt = 0
        self._pairs = {}
        self.lastClicked = []     
        self._all_points = []           
        self.create_widgets(parent)
        
        self.map_points = {}
        
        self.COLOR_ECU_AUTH = (255, 0, 0)
        self.COLOR_STR_AUTH = (0, 255, 0)
        self.COLOR_SIMPLE = (0, 0, 255)
        self.COLOR_EMPTY = (0, 0, 0)
            
    def _clicked(self, plot, points):  
              
        for p in self.lastClicked:
            p.resetPen()
                    
        try: info = points[0].data()
        except: info = False
        
        if info:
            try: info[5]
            except: info += [0, 0, 0, 0, 0]
            
            if info[2] == 'MonitorTags.CB_DONE_PROCESSING_MESSAGE':
                txt = "End of Transmission: BUS: %s\tMessage: %s\tSender: %s\nTime: %s"
            else:
                txt = "Start of Transmission: BUS: %s\tMessage: %s\tSender: %s\nTime: %s"
            
            self.label.setText(txt % (info[1], info[3], info[5], info[0]))

        for p in points:
            p.setPen('b', width=2)
        self.lastClicked = points   
                 
    def create_widgets(self, parent):
        vbox = QtGui.QVBoxLayout()        
        self.label = QtGui.QLabel()
        self.label.setText("Chainview")
        
        view = pg.GraphicsLayoutWidget(parent) 
        self.plot = view.addPlot()
        self.plot.setLabel('left', 'Buffer Events')
        self.plot.setLabel('bottom', 'Time [sec]')
        self.plot.showGrid(x=True, y=True)
        
        vbox.addWidget(self.label)
        vbox.addWidget(view)
        self.setLayout(vbox)
    
        
        # TEST 
#         self.update_gui([])
    
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
    
    def update_gui(self, monitor_input_lst):

        can_states = []
        if monitor_input_lst:
            can_states = monitor_input_lst[1]
                        
        
        for state in can_states:
            
            # Waiting for a pair: once found delete it ! MUAHAHA 
            try:
                me = self._pairs[state[4]]  # je nach TAG
                my_pair = state
                
            except:
                self._pairs[state[4]] = state
                continue
            
            try:
                self._sender_to_track[me[1]]
            except:
                self._sender_to_track[me[1]] = self._track_cnt
                self._track_cnt += 1
            
            start_t = me[0]
            track_pos = self._sender_to_track[me[1]]
            
            spots = []
            # start 
            arr = np.ndarray(2)
            arr[0] = start_t
            arr[1] = track_pos
            spots.append({'pos': arr, 'data': me, 'brush':pg.mkBrush(255, 255, 255, 120), 'symbol': 0, 'size': 8})
               
            # end
            arr = np.ndarray(2)
            arr[0] = my_pair[0]
            arr[1] = track_pos
            spots.append({'pos': arr, 'data': my_pair, 'brush':pg.mkBrush(255, 255, 255, 120), 'symbol': 1, 'size': 8})
                                                    
                                                    
            s2 = pg.ScatterPlotItem(size=10, pen=pg.mkPen('w'), pxMode=True)            
            s2.addPoints(spots)
    
            self.plot.addItem(s2)
            s2.sigClicked.connect(self._clicked)


                    
    def _get_last_num(self, stri):
        num = ""
        for el in stri[::-1]:
            if isnumeric(el):
                num += el
            else:
                break
        return num[::-1]
                    
    def _id_to_str(self, msg_id):
        
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
        return msg_id

    def _is_sec_mod(self, ecu):
        try:   
            ecu._SECMODULE
            return True              
        except:
            pass
        return False
