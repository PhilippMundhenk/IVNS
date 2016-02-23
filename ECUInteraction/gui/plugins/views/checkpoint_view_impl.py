from gui.plugins.views.abstract_viewer_plug import AbstractViewerPlugin
from PyQt4.Qt import QWidget
from PyQt4 import QtGui, QtCore
from PyQt4.QtGui import QHBoxLayout, QCheckBox, QHeaderView, \
    QTableWidgetItem, QColor, QVBoxLayout, QAbstractItemView
from gui.gui_builder import GBuilder
from io_processing.result_interpreter.checkpoint_interpreter import CheckpointInterpreter, \
    CPCategory
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter

class CheckpointViewPlugin(AbstractViewerPlugin):

    def __init__(self, *args, **kwargs):
        AbstractViewerPlugin.__init__(self, *args, **kwargs)
                
    def get_combobox_name(self):
        return "Checkpoints Analysis"

    def get_widget(self, parent):
        self.gui = CheckpointViewPluginGUI(parent)        
        return self.gui
    
    def get_interpreters(self):
        return [EventlineInterpreter]
        
    def load(self, data):
        self.gui.load(data)
    
    def save(self):
        return self.gui.save()
        
    def update_gui(self, interpreter_input): 

        self.gui.update_gui(interpreter_input)

class CheckpointViewPluginGUI(QWidget):
            
    def __init__(self, parent):
        QWidget.__init__(self, parent)

        self.create_widgets(parent)
            
        self._ecu_ids = []    
        self.prev = {}
        self.idx = {}
        self._plot_vals = {}
        self._extender = 1
        self._cp_collections = {}
        self._show_sets = {}        
        self._ex_comps = []
        
    def create_widgets(self, parent):
        
        hbox = QHBoxLayout()
        
        # Left side
        
        # Layout and Label
        vbox_left = QtGui.QVBoxLayout()      
        vbox_right = QtGui.QVBoxLayout()    
             
        # Header
        up_hbox = QHBoxLayout()
                
        self._label = QtGui.QLabel(self)
        self._label.setText("Choose the communication partner")      
        self._label.setFixedWidth(170)  
        self._ecu_1_label = QtGui.QLabel(self)
        self._ecu_1_label.setText("   ECU 1:")    
        self._ecu_1_label.setFixedWidth(50)
        self._ecu_2_label = QtGui.QLabel(self)
        self._ecu_2_label.setText("    ECU 2:")      
        self._ecu_2_label.setFixedWidth(50)     
        self._ecu_1_cb = GBuilder().combobox(self, [], self._on_ecu_selection_changed)
        self._ecu_1_cb.addItem("<< No Selection >>")
        self._ecu_1_cb.addItem("Unknown")
        self._ecu_2_cb = GBuilder().combobox(self, [], self._on_ecu_selection_changed)
        self._ecu_2_cb.addItem("<< No Selection >>")
        self._ecu_2_cb.addItem("Unknown")
        self._ass_cb = QCheckBox("Show only associated")
        self._ass_cb.setFixedWidth(130)
        self._ass_cb.stateChanged.connect(self._on_ecu_selection_changed)
        
        up_hbox.addWidget(self._label)
        up_hbox.addWidget(self._ecu_1_label)
        up_hbox.addWidget(self._ecu_1_cb)
        up_hbox.addWidget(self._ecu_2_label)
        up_hbox.addWidget(self._ecu_2_cb)
        up_hbox.addWidget(self._ass_cb)

        # Table
        self._time_table = GBuilder().table(self, 0, 3, ["Time", "ECU", 'Event'], False)
        self._time_table.setColumnWidth(0, 100)
        self._time_table.setColumnWidth(1, 170)
        self._time_table.setSortingEnabled(True)
        self._time_table.horizontalHeader().setResizeMode(0, QHeaderView.Fixed);
        self._time_table.horizontalHeader().setResizeMode(1, QHeaderView.Fixed);
        self._time_table.horizontalHeader().setResizeMode(2, QHeaderView.Stretch);
        
        # Layout
        vbox_left.addLayout(up_hbox)
        vbox_left.addWidget(self._time_table)
        
        # Right side
        v_lay = QVBoxLayout()
        self._times_gb = GBuilder().groupbox(self, "Times") 
        self._times_gb.setFixedWidth(450)
        self._times_gb.setLayout(v_lay)
        vbox_right.addWidget(self._times_gb)
        
        self._up_info = GBuilder().label(self, self._label_up("-", "-", "-", "-", "-"))
        self._down_info = GBuilder().label(self, self._label_down("-"))
        v_lay.addWidget(self._up_info)
        v_lay.addWidget(self._down_info)

        hbox.addLayout(vbox_left)
        hbox.addLayout(vbox_right)
        self.setLayout(hbox)
         
    def save(self):
        data = [self._cp_collections]
        return data
         
    def load(self, data):
        self.update_gui([data[0]])
         
    def update_gui(self, monitor_input_lst):

        # add new entries
        for monitor_input in monitor_input_lst:
            self._add_missing_keys(monitor_input[1])
             
            self._extend_table(monitor_input)
 
             
    def _extend_table(self, monitor_input):           
         
        # row already existing -> Continue
        txt = EventlineInterpreter().core.cp_string(eval(monitor_input[3]), monitor_input[2], monitor_input[7], monitor_input[5])

        txt_2 = str([monitor_input[0], monitor_input[1], txt])
        if txt_2 in self._ex_comps:
            return
          
        # insert a row at right point
        row_nr = self._get_suiting_row(self._time_table, monitor_input[0], 0)
          

          
        self._time_table.insertRow(row_nr)
          
        itab = TableCheckpointItem(); itab.set_checkpoint(monitor_input); itab.setText(str(monitor_input[0]));      
        itab_2 = TableCheckpointItem(); itab_2.set_checkpoint(monitor_input); itab_2.setText(monitor_input[1]);
        itab_3 = TableCheckpointItem(); itab_3.set_checkpoint(monitor_input); itab_3.setText(txt);
          
        self._time_table.setItem(row_nr, 0, itab);
        self._time_table.setItem(row_nr, 1, itab_2);
        self._time_table.setItem(row_nr, 2, itab_3);
        self._time_table.setSelectionBehavior(QAbstractItemView.SelectRows); 
        self._time_table.itemSelectionChanged.connect(self._selection_changed)
          
        self._set_row_color(self._time_table, EventlineInterpreter().core._category_by_tag(eval(monitor_input[3])), row_nr)
          
        # Add to show set
        self._show_sets[monitor_input[1]].add(row_nr, monitor_input[2])
        self._ex_comps.append(str([monitor_input[0], monitor_input[1], txt]))
                  
    def _add_missing_keys(self, comp_id):
             
        if comp_id not in self._ecu_ids:
            self._show_sets[comp_id] = TableShowSet(self._time_table)
             
            # Add entry to comboboxes
            self._ecu_1_cb.addItem(comp_id)
            self._ecu_2_cb.addItem(comp_id)            
            self._ecu_ids.append(comp_id)
        

    
    def _get_suiting_row(self, table, val, col_idx):
        ''' returns the row where val is bigger than the upper and smaller than the lower'''
        prev = 0
        for r in range(table.rowCount()):
            item = table.item(r, col_idx)            
            if val < float(item.text()):
                break            
            prev = r 
        return prev
         
    def _hide_all_rows(self, table):        
        for r in range(table.rowCount()):
            table.setRowHidden(r, True)
#         
    def _label_up(self, msg_id, msg_ctnt, msg_size, msg_cat, msg_stream):
        return "Checkpoint Details:\n\nMessage ID:\t\t\n%s\nMessage Content:\t\t\n%s\nMessage Size\t\t\n%s\nMessage Category\t\t\n%s\n Message Stream\t\t\n%s" % (msg_id, msg_ctnt, msg_size, msg_cat, msg_stream)
             
    def _label_down(self, time_passed):
        return"Selection Details:\nTime passed:%s" % (time_passed)
#             
    def _on_ecu_selection_changed(self):
        self._show_selection()
#     
    def _selection_changed(self):
         
        # show the first selected
        lst = self._time_table.selectedIndexes()
        for it in lst:
            r = it.row()
            c = it.column()            
            itm = self._time_table.item(r, c)
            cp = itm.checkpoint()
            self._up_info.setText(self._label_up(cp[4], cp[5], cp[6], EventlineInterpreter().core._category_by_tag(eval(cp[3])), cp[7]))
            break
         
        # Show the connected information
        if len(lst) > 4:
            itm_2 = self._time_table.item(lst[4].row(), lst[4].column())
            cp_2 = itm_2.checkpoint()
            self._down_info.setText(self._label_down(abs(cp.time - cp_2.time)))
         
         
        print(list)
     
    def _set_row_color(self, table, category, row_nr):
        red = QColor(255, 143, 143)
        green = QColor(204, 255, 204)
        blue = QColor(204, 230, 255)
         
        for c in range(table.columnCount()):
            item = table.item(row_nr, c)
         
            if category in [CPCategory.ECU_AUTHENTICATION_ENC, CPCategory.ECU_AUTHENTICATION_TRANS]:
                item.setData(QtCore.Qt.BackgroundRole, red);
                 
            if category in [CPCategory.STREAM_AUTHORIZATION_ENC, CPCategory.STREAM_AUTHORIZATION_TRANS]:
                item.setData(QtCore.Qt.BackgroundRole, green);
                 
            if category in [CPCategory.SIMPLE_MESSAGE_ENC, CPCategory.SIMPLE_MESSAGE_TRANS]:
                item.setData(QtCore.Qt.BackgroundRole, blue);
                 
    def _show_selection(self):
        try:
            # Hide all sets 
            self._hide_all_rows(self._time_table)
             
            # No selection made in either of the boxes -> show all
            if self._ecu_1_cb.currentText() == "<< No Selection >>" and self._ecu_2_cb.currentText() == "<< No Selection >>":
                for ky in self._show_sets:
                    self._show_sets[ky].show()
                return
                 
            # one of the boxes has no selection: show other
            if self._ecu_1_cb.currentText() == "<< No Selection >>":
                self._show_sets[self._ecu_2_cb.currentText()].show()
                return            
            if self._ecu_2_cb.currentText() == "<< No Selection >>":
                self._show_sets[self._ecu_1_cb.currentText()].show()
                return
             
            # Show all selected sets / option show only associated             
            # If show associated hit: Show only associated
            if self._ass_cb.isChecked():
                self._show_sets[self._ecu_1_cb.currentText()].show_asc(self._ecu_2_cb.currentText())
                self._show_sets[self._ecu_2_cb.currentText()].show_asc(self._ecu_1_cb.currentText())
                 
            # Show both
            else:
                self._show_sets[self._ecu_1_cb.currentText()].show()
                self._show_sets[self._ecu_2_cb.currentText()].show()
                 
        except:
            pass
 
class TableShowSet(object):
     
    def __init__(self, table):
        self._rows = []
        self._row_asc = {}  # associates a row to a value
        self._table = table
         
    def add(self, row_nr, association=False):
        self._rows.append(row_nr)
        if association:
            self._row_asc[row_nr] = association        
         
    def show(self):
        for r in self._rows:
            self._table.setRowHidden(r, False)
     
    def show_asc(self, asc_id):
        for r in self._rows:
            if r not in self._row_asc.keys(): return
            if self._row_asc[r] != asc_id: return
            self._table.setRowHidden(r, False)
     
    def hide(self):
        for r in self._rows:
            self._table.setRowHidden(r, True)
             
class TableCheckpointItem(QTableWidgetItem):
     
    def __init__(self, *args, **kwargs):
        QTableWidgetItem.__init__(self, *args, **kwargs)
 
        self._checkpoint = None
     
    def set_checkpoint(self, cp):
        self._checkpoint = cp
         
    def checkpoint(self):
        return self._checkpoint

