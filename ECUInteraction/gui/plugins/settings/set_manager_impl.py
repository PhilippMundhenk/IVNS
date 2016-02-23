'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''

from gui.plugins.settings.abstract_settings_plug import AbstractSettingsPlugin
from PyQt4.Qt import QWidget, QVBoxLayout, QHBoxLayout, QTableWidgetItem
from PyQt4 import QtGui, QtCore
from gui.gui_builder import GBuilder
from PyQt4.QtGui import QDialog
import os
from config.registrator import Registrator
import config.timing_registration as time
import traceback
from config.timing_db_admin import TimingDBMap

class SetManagerPlugin(AbstractSettingsPlugin):
    '''
    This class is the base class for all Widgets that are inserted into
    the GUI via a Plug In
    '''

    def __init__(self, *args, **kwargs):
        AbstractSettingsPlugin.__init__(self, *args, **kwargs)
        self._SETTINGS = False
        
        
    def get_combobox_name(self):
        return "Timing Set Manager"
        
    def get_widget(self, parent):        
        return SetManagerPluginGUI(parent)
    
class SetManagerPluginGUI(QWidget):
    
    def __init__(self, *args, **kwargs):
        QWidget.__init__(self, *args, **kwargs)
        self.builder = GBuilder()
        self.create_widgets()
            
         
                
    def create_widgets(self):   
        
        ''' Widgets'''
        self.desc_label = self.builder.label(self, "<b>Decription:</b> Configure the settings for the mapping Timing - Project Sets")
        self.desc_label.setFixedHeight(25)        
        self.desc_label.setFixedWidth(400)
                        
        self.selection_cb = self.builder.combobox(self, [], self.cb_selection_changed)
        self.selection_cb.setFixedHeight(25)
        
        self.sec_label = self.builder.label(self, "<b>Use Set: </b>")
        self.sec_label.setFixedHeight(25)
        self.sec_label.setFixedWidth(50)
                
        self.open_manager = self.builder.pushbutton(self, "Setting Manager", self._open_manager_act,\
                                                    icon_path =  os.getcwd() +r'/icons/settings.png')
        self.open_manager.setFixedHeight(35)
        
        
        ''' Layout '''
        vbox = QtGui.QVBoxLayout()
        
        hl = QtGui.QHBoxLayout()
        hl.addWidget(self.desc_label)
        hl.addWidget(self.open_manager)        
        vbox.addLayout(hl)
        
        hl = QtGui.QHBoxLayout()
        hl.addWidget(self.sec_label)
        hl.addWidget(self.selection_cb)        
        vbox.addLayout(hl)
        
        self.setLayout(vbox)
        
#         self.open_manager_act()
                
    def cb_selection_changed(self):
        pass
        
    def _open_manager_act(self):        
        man =  SettingManager()
        man.exec()
        

class SettingManager(QDialog):
    
    def __init__(self, *args, **kwargs):
        QDialog.__init__(self, *args, **kwargs)
    
        self.builder = GBuilder()        
        self.setWindowIcon(QtGui.QIcon( os.getcwd() +r'/icons/tumcreatelogo2.png'))
        self.setWindowTitle("Timing Set Manager")    
        self.selected_tab_row = 0
        
        self.create_widgets()        
        
        self._load_variables()   

    def create_widgets(self):
        
        ''' Create Widgets'''
        self.builder.set_props(self, False, 1200, 740)

        self.desc_label = self.builder.label(self, "Description: \nEdit an existing Timing Mapping Parameter Set or create a new one")
        self.desc_label.setFixedHeight(50)
        
        self.set_cb = self.builder.combobox(self, [], self.set_cb_selection_changed)
        self.set_cb.setFixedHeight(22)
        
        self.set_plus_pb = self.builder.pushbutton(self, "Add", self.add_hit, os.getcwd() +r'/icons/add.png')
        self.set_plus_pb.setFixedWidth(100)
        self.set_plus_pb.setFixedHeight(30)
                
        self.elem_tab = self.builder.table(self, 0, 5, ["Affiliation", "Timing Variable", "Type", "Value", "Condition"])        
        self.elem_tab.cellDoubleClicked.connect(self._cell_double_clicked)
        
        ''' Save and Exit Buttons '''        
        self.space = self.builder.label(self, "")
#         self.space.setFixedWidth(300)
        self.ok_pb = self.builder.pushbutton(self, "Ok", self.ok_hit)
        self.ok_pb.setFixedHeight(30)
        self.ok_pb.setFixedWidth(140)
        self.apply_pb = self.builder.pushbutton(self, "Apply", self.apply_hit)
        self.apply_pb.setFixedHeight(30)
        self.apply_pb.setFixedWidth(140)
        self.cancel_pb = self.builder.pushbutton(self, "Cancel", self.cancel_hit)
        self.cancel_pb.setFixedHeight(30)
        self.cancel_pb.setFixedWidth(140)
                
        ''' Layout '''
        v_lay = QVBoxLayout()        
        v_lay.addWidget(self.desc_label)
        
        hl = QHBoxLayout()
        hl.addWidget(self.set_plus_pb)
        hl.addWidget(self.set_cb)
        v_lay.addLayout(hl)
        
        v_lay.addWidget(self.elem_tab)     
        
        hl = QHBoxLayout()
        hl.addWidget(self.space)
        hl.addWidget(self.ok_pb)
        hl.addWidget(self.cancel_pb)   
        hl.addWidget(self.apply_pb)
        v_lay.addLayout(hl)
        
        self.setLayout(v_lay)       
        
    def _load_variables(self):
        ''' Load all timing Variables that are specified in the timing.ini '''
        timing_vars = []
        self.db_lookup_dict = {}
        
        ''' 1. Load the variables '''
        for reg_tim in Registrator().reg_simple_timings.keys():
            for l in Registrator().reg_simple_timings[reg_tim]:
                dic = Registrator().reg_simple_timings[reg_tim][l]
                
                lst = list(dic.keys())
                try:                            
                    lst += Registrator().db_lookup_timings[reg_tim][l]
                    self.db_lookup_dict[l] = list(Registrator().db_lookup_timings[reg_tim][l].keys())
                except:
                    pass
    
                timing_vars.append([l, lst, reg_tim, dic])
                
        ''' 2. Set table from variables'''
        self._set_timing_tab(timing_vars)
        
    def _set_timing_tab(self, timing_vars):
                
        self.elem_tab.setRowCount(len(timing_vars))
        self.db_lookup_idx_to_info = {}
             
        self.type_cb_to_idx = {}
        self.type_idx_to_cb = {}
        self.type_item_state = {}
        self.type_to_dict = {}
                
        for i in range(len(timing_vars)):
            
            cur_var = timing_vars[i][0]
            cur_vals = timing_vars[i][1]
            cur_ass = timing_vars[i][2]
            cur_vals_dict = timing_vars[i][3]            
                        
            ''' 1. Set Variable Name '''
            self.elem_tab.setItem(i, 0, QTableWidgetItem(cur_ass))
            self.elem_tab.setItem(i, 1, QTableWidgetItem(cur_var))
            self.elem_tab.setItem(i, 2, QTableWidgetItem())
            self.type_to_dict[cur_var] = cur_vals_dict            
            
            ''' 2. Set Setting '''
            wid = QWidget()
            vl = QVBoxLayout()
            cb = self.builder.combobox(self, cur_vals + ["new Setting ..."], self.on_type_cb_itemchanged)
            self.type_cb_to_idx[str(cb)] = i
            self.type_idx_to_cb[i] = cb
            cb.setFixedHeight(20)            
            vl.addWidget(cb)
            wid.setLayout(vl)
            self.elem_tab.setCellWidget(i, 2, wid)            
            self.type_item_state[i] = cb.currentText()
            
            ''' 3. Set value'''
            self.elem_tab.setItem(i, 3, QTableWidgetItem(str(cur_vals_dict[cb.currentText()])))
            
    def on_type_cb_itemchanged(self):
        ''' changed index if new Setting hit create new Setting'''
        
        for i in range(self.elem_tab.rowCount()):
            try:
                cb = self.type_idx_to_cb[i]
                if(cb.currentText() == "new Setting ..."):
                    idx = cb.findText(self.type_item_state[i])
                    cb.setCurrentIndex(idx)                    
                    self.new_setting(i)
                    continue
                
                if cb.currentText() != self.type_item_state[i] and cb.currentText() != 'CUSTOMIZED':
                    ''' load values '''#                     
                    itm = self.elem_tab.item(i, 1)
                    txt = itm.text()
                    cor_dic = self.type_to_dict[txt]
                    try:
                        val = cor_dic[cb.currentText()]                    
                        self.elem_tab.setItem(i, 3, QTableWidgetItem(str(val)))
                    except:
                        pass
                    
                    self.db_lookup_dict[txt]
                    
                    itm1 = self.elem_tab.item(i, 0)
                    itm2 = self.elem_tab.item(i, 1)
                    
                    ''' if DB Lookup show request -> double click opens window: edit request and edit the condition '''
                    [request, spec] = TimingDBMap().lookup_from_spec(itm1.text(), itm2.text(), cb.currentText())
                    [condition, spec] = TimingDBMap().conditions_from_spec(itm1.text(), itm2.text(), cb.currentText())                    
                    itm = QTableWidgetItem(request)                    
                    self.elem_tab.setItem(i, 4, itm)
                    itm.setToolTip("Conditions: \n%s" % self._pretty_str_cond(condition))
                    self.db_lookup_idx_to_info[i] = [condition, request, spec]
                        
                self.type_item_state[i] = cb.currentText()
            except:
                pass
            
        
    def _pretty_str_cond(self, conditions):
        out_str = ""
        
        for el in conditions:
            out_str += "\nName:\t\t"
            out_str += el['name']
            out_str += "\nConfig:\t\t"
            out_str += str(el['config'])
            out_str += "\nValue:\t\t"
            out_str += str(el['value'])
            out_str += "\n"
            
        return out_str
            
    def _cell_double_clicked(self, row, col):
        print("DOUBLE CLICKED row %s" % row)
        try:
            [condition, request, spec] = self.db_lookup_idx_to_info[row]
            DBElemEditor(condition, request, spec, self.elem_tab.item(row, 4))

        except:
            pass

    def new_setting(self, row):
        print("Create new setting in row %s" % row)
        
    
    def add_hit(self):
        print("asd")
    
    def ok_hit(self):
        print("ok")
    
    def apply_hit(self):
        print("Apply")
    
    def cancel_hit(self):
        self.close()
    
    def set_cb_selection_changed(self):
        pass
    
    
    
    
class DBElemEditor(QDialog):
    
    def __init__(self, condition, request, spec, q_tab_item):
        QWidget.__init__(self)
        
        self.builder = GBuilder()
        
        self.edited_item = q_tab_item
        self.condition = condition
        self.request = request
        self.spec_node = spec
        
        self._create_widget()
        
        self._fill_widgets()
        
        self.exec()
        
    def _create_widget(self):
        
        self.builder.set_props(self, False, 820, 300)
        self.setWindowIcon(QtGui.QIcon( os.getcwd() +r'/icons/tumcreatelogo2.png'))
        
        self.tit_label = self.builder.label(self, "Description: \nEdit the Database request and the conditions")
            
        self.left_label = self.builder.label(self, "Database request:")    
        
        self.db_textbox = QtGui.QTextEdit()
    
    
        self.cond_label = self.builder.label(self, "Conditions for Database with ID:") 
        self.condition_tab = self.builder.table(self, len(self.condition), 6, ["ID", 'Lookup DB', "Var Name", "Var Config", "Type", "Value"], False)
        self.condition_tab.verticalHeader().hide()
        self.condition_tab.setColumnWidth(2, 250)
        
        
        self.add_pb = self.builder.pushbutton(self, "Add Item", self.add_hit, icon_path = os.getcwd() +r'/icons/add.png')
        self.add_pb.setFixedHeight(30)
        self.add_pb.setFixedWidth(200)
        self.del_pb = self.builder.pushbutton(self, "Delete Item", self.delete_hit, icon_path = os.getcwd() +r'/icons/delete.png')
        self.del_pb.setFixedHeight(30)
        self.del_pb.setFixedWidth(200)
        
        
        self.space = self.builder.label(self, "")
        self.ok_pb = self.builder.pushbutton(self, "Ok", self.ok_hit)
        self.ok_pb.setFixedHeight(30)
        self.ok_pb.setFixedWidth(140)
        self.cancel_pb = self.builder.pushbutton(self, "Cancel", self.cancel_hit)
        self.cancel_pb.setFixedHeight(30)
        self.cancel_pb.setFixedWidth(140)
                
    
        ''' Layout '''
        v_lay = QVBoxLayout()
        
        v_lay.addWidget(self.tit_label)
        
        v_lay.addWidget(self.left_label)
    
        v_lay.addWidget(self.db_textbox)
        v_lay.addWidget(self.cond_label)
        v_lay.addWidget(self.condition_tab)
    
        hl = QHBoxLayout()
        hl.addWidget(self.add_pb)
        hl.addWidget(self.del_pb) 
        
        hl.addWidget(self.space)
        hl.addWidget(self.ok_pb)
        hl.addWidget(self.cancel_pb)   
        v_lay.addLayout(hl)
    
        self.setLayout(v_lay)
    
    def _fill_widgets(self):
        
        self.db_textbox.setText(self.request)
        
        db_path = self.spec_node.attrib['dbpath']
        spec_id = self.spec_node.attrib['id']
        found_vars = self.spec_node.findall('{http://www.tum-create.edu.sg/timingSchema}variable')
        if found_vars == None: return
        
        i = 0
        for var in found_vars:
            var_name = var.attrib['name']
            var_config = var.attrib['config']
            var_type = var.attrib['type']
        
            val = var.find('{http://www.tum-create.edu.sg/timingSchema}value')
            if val == None: return
            var_value = val.text

            self.condition_tab.setItem(i, 0, QTableWidgetItem(spec_id))
            self.condition_tab.setItem(i, 1, QTableWidgetItem(db_path))
            self.condition_tab.setItem(i, 2, QTableWidgetItem(var_name))
            self.condition_tab.setItem(i, 3, QTableWidgetItem(var_config))
            self.condition_tab.setItem(i, 4, QTableWidgetItem(var_type))
            self.condition_tab.setItem(i, 5, QTableWidgetItem(var_value))
    
            i += 1
    
    def add_hit(self):                
        self.condition_tab.setRowCount(self.condition_tab.rowCount() + 1)
        
    def delete_hit(self):                
        cur_row = self.condition_tab.currentRow()
        self.condition_tab.removeRow(cur_row)
        
    
    def ok_hit(self):
#         !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        '''
        CONTINUE HERE:
            TODO: 
                Read out changes from the table and write it back to the timing Mapping file and save it (but only after Editor closed)
  
        '''
        for i in range(self.condition_tab.rowCount()): 
            for j in range(self.condition_tab.columnCount()):            
                itm = self.condition_tab.item(i, j)
                if j == 0: k = 1
            
        
        
        
        
        
        print("ok")
        
    def cancel_hit(self):
        self.close()
    
    