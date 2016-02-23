from gui.plugins.views.abstract_viewer_plug import AbstractViewerPlugin
from PyQt4.Qt import QWidget
from PyQt4 import QtGui
import pyqtgraph as pg
import numpy as np
from numpy.core.defchararray import isnumeric
from config import can_registration
from io_processing.surveillance_handler import MonitorInput, MonitorTags
from io_processing.result_interpreter.buffer_interpreter import BufferInterpreter
from PyQt4.QtGui import QHBoxLayout, QCheckBox
from gui.gui_builder import GBuilder


class BufferViewPlugin(AbstractViewerPlugin):

    def __init__(self, *args, **kwargs):
        AbstractViewerPlugin.__init__(self, *args, **kwargs)
                
    def get_combobox_name(self):
        return "Buffer States"

    def get_widget(self, parent):
        self.gui = BufferViewPluginGUI(parent)        
        return self.gui
    
    def get_interpreters(self):
        return [BufferInterpreter]
        
    def link_axis(self):
        '''this method returns a plot that will be linked to 
           the x Axis of the other plots'''
        return self.gui.link_axis()
        
    def load(self, data):
        self.gui.load(data)
    
    def save(self):
        return self.gui.save()
    
    def update_gui(self, interpreter_input): 
        self.gui.update_gui(interpreter_input)

class BufferViewPluginGUI(QWidget):
            
    def __init__(self, parent):
        QWidget.__init__(self, parent)

        self.create_widgets(parent)
                        
        self._ecu_ids = []    
        self.prev = {}
        self.idx = {}
        self._plot_vals = {}
        self._extender = 1
        
        
    def create_widgets(self, parent):
        
        # Layout and Label
        vbox = QtGui.QVBoxLayout()        
        self.label = QtGui.QLabel()
        self.label.setText("Buffer View")
        
        # Plot and Curves
        view = pg.GraphicsLayoutWidget(parent) 
        self.plot = view.addPlot(title="Buffer View")
        self.plot.setLabel('left', 'Buffer Memory [B]')
        self.plot.setLabel('bottom', 'Time [sec]')
        
        self.plot.showGrid(x=True, y=True)
        self.plot_1 = self.plot.plot(pen=(255, 0, 0), name="Red curve", fillLevel=0, fillBrush=(255, 255, 255, 30))        
        self.plot_2 = self.plot.plot(pen=(0, 255, 0), name="Green curve", fillLevel=0, fillBrush=(255, 255, 255, 30))     
        
        
        # Combobox
        self.ecu_selection_cb = GBuilder().combobox(self, [], self._ecu_selection_changed)

        # Checkbuttons
        h_lay = QHBoxLayout()
        self.transmit_cb = QCheckBox("Transmit Buffer (red)")
        self.transmit_cb.setFixedWidth(150)
        self.transmit_cb.setFixedHeight(20)
        self.transmit_cb.setChecked(True)
        self.transmit_cb.stateChanged.connect(self._ecu_selection_changed)
        self.receive_cb = QCheckBox("Receive Buffer (green)")
        self.receive_cb.setFixedWidth(150)
        self.receive_cb.setChecked(True)
        self.receive_cb.setFixedHeight(20)
        self.receive_cb.stateChanged.connect(self._ecu_selection_changed)
        
        # Layout
        vbox.addWidget(self.label)
        vbox.addWidget(view)
        h_lay.addWidget(self.ecu_selection_cb)
        h_lay.addWidget(self.transmit_cb)
        h_lay.addWidget(self.receive_cb)
        vbox.addLayout(h_lay)
        self.setLayout(vbox)
      
    def save(self):
        return [self._plot_vals, self._ecu_ids]
        
    def link_axis(self):
        return self.plot
        
    def load(self, data):
        self._plot_vals = data[0]
        
        for el in data[1]:
            self.ecu_selection_cb.addItem(el)
        
        self._plot_it()
        
    def update_gui(self, monitor_input_lst):
                
        for monitor_input in monitor_input_lst:
            
            data = float(monitor_input[9])
            
            # Check if ECU available and add it to combobox
            tag = eval(monitor_input[3])      
            try:   
                self._add_ecu(monitor_input[1])
            except:
                pass
            
            # Update View
            try:
                # Extract data
                cur_id = monitor_input[1]
                t = monitor_input[0]
                cur_idx = self.idx[tag][cur_id]
        
                # extend array
                self._extend_array(cur_idx, monitor_input)
                          
                # Check format
                if self._wrong_data_format(data, tag, cur_id, cur_idx, t):
                    continue                                
                
                # Extend plot values
                self._extend_plot_vals(tag, cur_id, cur_idx, t, data)
            except:
                pass
                    
            # Plot values
            self._plot_it()
       
    def _add_ecu(self, ecu_id):    
        ''' 
        adds the ecu to the view if needed
        '''
        if not ecu_id in self._ecu_ids:
            if not self._text_in_cb(ecu_id, self.ecu_selection_cb):
                self.ecu_selection_cb.addItem(ecu_id)
                self._ecu_ids.append(ecu_id)
                
                for in_tag in [MonitorTags.BT_ECU_TRANSMIT_BUFFER, MonitorTags.BT_ECU_RECEIVE_BUFFER]:
                    if in_tag not in self.idx: self.idx[in_tag] = {}
                    if in_tag not in self.prev: self.prev[in_tag] = {}
                    if in_tag not in self._plot_vals: self._plot_vals[in_tag] = {}
                    
                    self.idx[in_tag][ecu_id] = 0
                    self.prev[in_tag][ecu_id] = -1
                    self._plot_vals[in_tag][ecu_id] = np.zeros((50000, 2), dtype=float)
       
    def _extend_array(self, cur_idx, monitor_input):
        if cur_idx >= (50000 * self._extender):
            self._plot_vals[MonitorTags.BT_ECU_TRANSMIT_BUFFER][monitor_input[1]] = np.concatenate((self._plot_vals[MonitorTags.BT_ECU_TRANSMIT_BUFFER][monitor_input[1]], np.zeros((50000, 2), dtype=float)))
            self._plot_vals[MonitorTags.BT_ECU_RECEIVE_BUFFER][monitor_input[1]] = np.concatenate((self._plot_vals[MonitorTags.BT_ECU_RECEIVE_BUFFER][monitor_input[1]], np.zeros((50000, 2), dtype=float)))
            self._extender += 1
       
    def _extend_plot_vals(self, tag, cur_id, cur_idx, t, data):
        self.prev[tag][cur_id] = t
        self._plot_vals[tag][cur_id][cur_idx][0] = t
        self._plot_vals[tag][cur_id][cur_idx][1] = data  # y val                
        self.idx[tag][cur_id] += 1
    
    def _plot_it(self):        
        try:            
            if self.transmit_cb.isChecked():
              
                vals = self._plot_vals[MonitorTags.BT_ECU_TRANSMIT_BUFFER][self.ecu_selection_cb.currentText()]                
                vals = vals[~np.all(vals == 0, axis=1)]
                
                self.plot_1.setData(vals)
                self.plot_1.show()
            else:
                self.plot_1.hide()
        except:
            pass
        try:
            if self.receive_cb.isChecked():
                vals = self._plot_vals[MonitorTags.BT_ECU_RECEIVE_BUFFER][self.ecu_selection_cb.currentText()]
                vals = vals[~np.all(vals == 0, axis=1)]
                self.plot_2.setData(vals)
                self.plot_2.show()
            else:
                self.plot_2.hide()
        except:
            pass
       
    def _ecu_selection_changed(self):
        try:
            print(self.ecu_selection_cb.currentText())
        except:
            pass        
        self._plot_it()
                    
    def _text_in_cb(self, txt, combobox):
        for i in range(combobox.count()):
            if txt == combobox.itemText(i):
                return True
        return False
        
    def _wrong_data_format(self, data, tag, cur_id, cur_idx, t):
        if not isinstance(data, (int, float, complex)):
            return True            
        if t < self.prev[tag][cur_id]:
            return True           
        if cur_idx > 1:
            test = cur_idx - 1
        else:
            test = 0    
        if (self._plot_vals[tag][cur_id][test][0] == t):
            return True   
        return False
