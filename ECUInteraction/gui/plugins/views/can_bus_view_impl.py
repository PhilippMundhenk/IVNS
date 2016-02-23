from gui.plugins.views.abstract_viewer_plug import AbstractViewerPlugin
from PyQt4.Qt import QWidget
from PyQt4 import QtGui
import pyqtgraph as pg
import numpy as np
from gui.gui_builder import GBuilder
from io_processing.result_interpreter.can_bus_interpreter import CanBusInterpreter
from PyQt4.QtGui import QHBoxLayout


class CanBusViewPlugin(AbstractViewerPlugin):

    def __init__(self, *args, **kwargs):
        AbstractViewerPlugin.__init__(self, *args, **kwargs)
                
    def get_combobox_name(self):
        return "Can Bus Datarate"

    def get_widget(self, parent):
        self.gui = CanBusViewPluginGUI(parent)        
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
        

class CanBusViewPluginGUI(QWidget):
            
    def __init__(self, parent):
        QWidget.__init__(self, parent)

        self.create_widgets(parent)
                        
        self._bus_ids = []    
        self.prev = {}
        self.idx = {}
        self._plot_vals = {}
        self._extender = 1
        
        self._last_time = {}
        
        
    def create_widgets(self, parent):
        
        # Layout and Label
        vbox = QtGui.QVBoxLayout()        
        self.label = QtGui.QLabel()
        self.label.setText("Bus View")
        
        # Plot and Curves
        view = pg.GraphicsLayoutWidget(parent) 
        self.plot = view.addPlot(title="Bus View")
        self.plot.showGrid(x=True, y=True)
        self.plot_1 = self.plot.plot(pen=(255, 0, 0), name="Red curve", fillLevel=0, fillBrush=(255, 255, 255, 30))        
    
        self.plot.setLabel('left', 'Datarate [KB/s]')
        self.plot.setLabel('bottom', 'Time [sec]')
    
        # Combobox
        self.bus_selection_cb = GBuilder().combobox(self, [], self._ecu_selection_changed)

        # Checkbuttons
        h_lay = QHBoxLayout()
        
        # Layout
        vbox.addWidget(self.label)
        vbox.addWidget(view)
        h_lay.addWidget(self.bus_selection_cb)
        vbox.addLayout(h_lay)
        self.setLayout(vbox)
      
    def save(self):
        return [self._plot_vals, self._bus_ids]
        
    def load(self, data):
        self._plot_vals = data[0]
        for el in data[1]:
            self.bus_selection_cb.addItem(el)
        self._plot_it()
        
    def update_gui(self, datarates_l):
                
        datarates = datarates_l[0]
                
        for bus_id in datarates:


            info = datarates[bus_id]
            t_0 = info[0]  
            rate = info[2]
                        
            # Check if BUs available and add it to combobox
            try:   
                self._add_bus(bus_id)
            except:
                pass

            # Update View
            try:

                cur_idx = self.idx[bus_id]

                # extend array
                self._extend_array(cur_idx, bus_id)

                # Extend plot values
                self._extend_plot_vals(bus_id, cur_idx, t_0, rate)
                
            except:
                pass
                     
        # Plot values
        self._plot_it()
       
    def _add_bus(self, bus_id):    
        ''' 
        adds the ecu to the view if needed
        '''
        if not bus_id in self._bus_ids:
            if not self._text_in_cb(bus_id, self.bus_selection_cb):
                self.bus_selection_cb.addItem(bus_id)
                self._bus_ids.append(bus_id)
                
                self._last_time[bus_id] = 0
                self.idx[bus_id] = 0
                self.prev[bus_id] = -1
                self._plot_vals[bus_id] = np.zeros((50000, 2), dtype=float)
       
    def _extend_array(self, cur_idx, bus_id):
        if cur_idx >= (50000 * self._extender):
            self._plot_vals[bus_id] = np.concatenate((self._plot_vals[bus_id], np.zeros((50000, 2), dtype=float)))
            self._plot_vals[bus_id] = np.concatenate((self._plot_vals[bus_id], np.zeros((50000, 2), dtype=float)))
            self._extender += 1
       
    def _extend_plot_vals(self, cur_id, cur_idx, t, data):
        
        self.prev[cur_id] = t
        self._plot_vals[cur_id][cur_idx][0] = t
        self._plot_vals[cur_id][cur_idx][1] = data  # y val                
        self.idx[cur_id] += 1
    
    def _plot_it(self):        
        try:
            vals = self._plot_vals[self.bus_selection_cb.currentText()]                
            vals = vals[~np.all(vals == 0, axis=1)]
            
            self.plot_1.setData(vals)
            self.plot_1.show()
        except:
            pass
       
    def _ecu_selection_changed(self):
        try:
            print(self.bus_selection_cb.currentText())
        except:
            pass        
        self._plot_it()
                    
    def _text_in_cb(self, txt, combobox):
        for i in range(combobox.count()):
            if txt == combobox.itemText(i):
                return True
        return False
        
    def _wrong_data_format(self, data, cur_id, cur_idx, t):
        if not isinstance(data, (int, float, complex)):
            return True            
        if t < self.prev[cur_id]:
            return True           
        if cur_idx > 1:
            test = cur_idx - 1
        else:
            test = 0    
        if (self._plot_vals[cur_id][test][0] == t):
            return True   
        return False
