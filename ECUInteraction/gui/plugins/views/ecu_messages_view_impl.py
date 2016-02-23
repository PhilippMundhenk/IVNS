'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''
from gui.plugins.views.abstract_viewer_plug import AbstractViewerPlugin

from PyQt4 import QtGui, QtCore
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter, \
    CheckpointInterpreterCore
from math import floor
from gui.gui_builder import GBuilder
from pyqtgraph import dockarea
from PyQt4.QtGui import QSpacerItem, QTextEdit, QHBoxLayout
from tools.ecu_logging import ECULogger
from io_processing.result_interpreter.constellation_interpreter import ConstellationInterpreter
from api.core.api_core import APICore

class ECUMessagesViewPlugin(AbstractViewerPlugin):

    def __init__(self, *args, **kwargs):
        AbstractViewerPlugin.__init__(self, *args, **kwargs)
        
    def get_combobox_name(self):
        return "ECU Messages"

    def get_widget(self, parent):
        self.gui = ECUMessagesViewPluginGUI(parent)
        return self.gui
    
    def get_interpreters(self):
        return [EventlineInterpreter, ConstellationInterpreter]
    
#     def link_axis(self):
#         return self.gui.plot
        
    def load(self, data):
        self.gui.load(data)
    
    def save(self):
        return self.gui.save()
    
    def update_gui(self, interpreter_input): 
        self.gui.update_gui(interpreter_input)

class ECUMessagesViewPluginGUI(dockarea.DockArea):
            
    def __init__(self, parent):
        dockarea.DockArea.__init__(self)
                
        self.builder = GBuilder()  
        self.widget_index = {} 
        self.widget_text = {}
        self.dock_index = {}
        
        self._external_core = CheckpointInterpreterCore()
        self._information_box_items = ['Time', 'Associated Id', 'Monitor Tag', 'Message Id', 'Message', 'Size', 'Stream Id', 'Monitor Data', 'Description']
        self._information_checked = {'Time': True, 'Associated Id': True, 'Monitor Tag': True, 'Message Id': True, 'Message': True, 'Size': True, 'Stream Id': False, 'Monitor Data': False, 'Description': True}
        self._info_widget_index = {}
        self.known = []      
        
        self.create_widgets(parent)              
            
    def _already_there(self, mon_input): 
        ''' handles duplicates'''
        if hash(mon_input) in self.known: 
            return True      
        self.known.append(hash(mon_input))
        if len(self.known) > 1000:
            del self.known[:floor(float(len(self.known)) / 2.0)]
        return False
    
            
    def create_widgets(self, parent):
        
        h_layout = QHBoxLayout()
        self.viewer_cbox = self.builder.checkable_combobox(parent, [], self._set_cb_changed)
        self.information_cbox = self.builder.checkable_combobox(parent, [], self._set_information_changed)
        self.information_cbox.setFixedWidth(150)
        cnt = 0
        for info in self._information_box_items:
            self.information_cbox.addItem(info)        
            new_row = self.information_cbox.count() - 1
            item = self.information_cbox.model().item(new_row, 0)
            if self._information_checked[info]:
                item.setCheckState(QtCore.Qt.Checked)
            else:
                item.setCheckState(QtCore.Qt.Unchecked)
            self._info_widget_index[cnt] = info
            cnt += 1
        
        h_layout.addWidget(self.viewer_cbox)
        h_layout.addItem(QSpacerItem(10, 10))
        h_layout.addWidget(self.information_cbox)
        
        # add ecu selection
        self.label_top = QtGui.QLabel()
        self.label_top.setText("Message View")
        self.viewDock = dockarea.Dock('view', size=(1000, 600))
        self.layout.addWidget(self.label_top)
        self.label_top.setFixedHeight(20)
        self.layout.addLayout(h_layout)        
        self.layout.addItem(QSpacerItem(10, 10))

    def _set_information_changed(self, e):
        
        # get checked items
        checked_idx = []
        for cnt in range(self.information_cbox.count()):
            item = self.information_cbox.model().item(cnt, 0)
            if item.checkState():                
                checked_idx.append(cnt)
        
        # checked items set them 
        for idx in self._info_widget_index.keys():
        
            info = self._info_widget_index[idx]
            if idx in checked_idx:
                self._information_checked[info] = True
            else: 
                self._information_checked[info] = False

    def _add_items_ecu_ids(self, ecu_ids):
        items = []
        for ecu_id in ecu_ids:
            try:
                items += [self.add_item(ecu_id)]
            except:
                pass
        
        if not items: return
        
        for i in items:
            i.setCheckState(QtCore.Qt.Unchecked)
        items[0].setCheckState(QtCore.Qt.Checked) 
        self._set_cb_changed(None)
        
    def add_item(self, title_text):
        
        # add item to dock                
        new_widget = QTextEdit()
        new_widget.setText("")
        new_widget.setReadOnly(True)
        
        new_dock = dockarea.Dock(title_text, size=(1000, 20))
        new_dock.setOrientation('horizontal')
        new_dock.addWidget(new_widget)
        
        self.addDock(new_dock, 'right')
        
        # add item to combobox
        self.viewer_cbox.addItem(title_text)        
        new_row = self.viewer_cbox.count() - 1
        item = self.viewer_cbox.model().item(new_row, 0)
        item.setCheckState(QtCore.Qt.Checked)
        
        
        # link items
        self.widget_index[new_row] = new_widget
        self.widget_text[title_text] = new_widget
        self.dock_index[new_row] = new_dock
        
        return item
        
        
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
    
    def save(self):
        return []
    
    def load(self, val_pairs):
        pass
    
    
    def update_gui(self, monitor_input_list):

        
        # receive the ecu ids
        try: 
            if isinstance(monitor_input_list[0], str): return
            
            constellation = monitor_input_list[0].data
            ecu_groups = constellation[0]
            ecu_ids = [e.ecu_id for e in APICore()._ecu_list_from_groups(ecu_groups)]
            self._add_items_ecu_ids(ecu_ids)   
            return         
        except: 
            pass
        
        monitor_input_list.sort(key=lambda x: x[0], reverse=False)

        # receive simple inputs
        for monitor_input in monitor_input_list:
            # read information
            time = monitor_input[0]
            ecu_id = monitor_input[1]
            associated_id = monitor_input[2]
            tag = eval(monitor_input[3])
            message_id = monitor_input[4]
            message = monitor_input[5]
            message_size = monitor_input[6]
            stream_id = monitor_input[7]
            unique_id = monitor_input[8]
            input_data = monitor_input[9]
            description = self._external_core.cp_string(tag, associated_id, stream_id, message)
            
            # get textedit
            text_edit = self.widget_text[ecu_id]
#             current_text = text_edit.toPlainText()
            
            # create new text
            part_append = ""
                        
            if self._information_checked['Time']: part_append += "\n\nTime: \t%s" % time
            if self._information_checked['Associated Id']: part_append += "\nAssociated Id: \t%s" % associated_id
            if self._information_checked['Monitor Tag']: part_append += "\nMonitor Tag: \t%s" % tag
            if self._information_checked['Message Id']: part_append += "\nMessage Id: \t%s" % message_id
            if self._information_checked['Message']: part_append += "\nMessage: \t%s" % message
            if self._information_checked['Size']: part_append += "\nSize: \t%s" % message_size
            if self._information_checked['Stream Id']: part_append += "\nStream Id: \t%s" % stream_id
            if self._information_checked['Monitor Data']: part_append += "\nMonitor Data: \t%s" % input_data
            if self._information_checked['Description']: part_append += "\nDescription: \t%s" % description

            # add new part
            text_edit.append(part_append)
#             current_text += part_append
#             text_edit.setText(current_text)
            text_edit.verticalScrollBar().setValue(text_edit.verticalScrollBar().maximum());
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
                        
               

        

        
