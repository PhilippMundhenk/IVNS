'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''
from uuid import uuid4
'''===============================================================================
    GUI Part
==============================================================================='''

import os
import traceback

from PyQt4 import QtGui, QtCore
from PyQt4.Qt import QWidget, QObject
from PyQt4.QtCore import Qt, QPoint
from PyQt4.QtGui import QHBoxLayout, QVBoxLayout, QDialog, QGridLayout, QScrollArea, \
    QHeaderView, QComboBox, QStackedWidget, QMessageBox, QAction

import api
from api.api_core import ECUFactory, BusFactory
from gui.gui_builder import GBuilder, DragLabel, DragSelection, LineConnection, \
    EnvironmentView
from gui.plugins.settings.abstract_settings_plug import AbstractSettingsPlugin
from tools.ecu_logging import ECULogger
from tools.singleton import Singleton


class CreateSimulationPlugin(AbstractSettingsPlugin):
    '''
    This plugin offers the possibility to create, save and build a simulation 
    via a GUI instead of using the API
    '''

    def __init__(self, *args, **kwargs):
        AbstractSettingsPlugin.__init__(self, *args, **kwargs)    
        self._SETTINGS = True

    def get_combobox_name(self):
        return "Create Simulation"

    def get_widget(self, parent):        
        return CreateSimulationPluginGUI(parent)

class CreateSimulationPluginGUI(QWidget):
    
    def __init__(self, parent):
        QWidget.__init__(self, parent)        
        self.create_widgets(parent)
                
    def create_widgets(self, parent):
        
        # Main Layout
        vbox = QtGui.QVBoxLayout()     
        self.setLayout(vbox)
        
        # Label
        vl_left = QVBoxLayout()
        self.top_label = GBuilder().label(parent, "Create a new Simulation or select a existing one from the list", None, None)
        vl_left.addWidget(self.top_label)        
        hl_out = QHBoxLayout()
        vbox.addLayout(hl_out)
        
        # Buttons
        vl_right = QVBoxLayout()
        self.new_button = GBuilder().pushbutton(parent, "New", self._new_hit, os.getcwd() + r'/icons/new.png')
        vl_right.addWidget(self.new_button)   
        self.import_button = GBuilder().pushbutton(parent, "Import", self._import_hit, os.getcwd() + r'/icons/import.png')
        vl_right.addWidget(self.import_button)            
        self.save_button = GBuilder().pushbutton(parent, "Export", self._save_hit, os.getcwd() + r'/icons/save.png')
        vl_right.addWidget(self.save_button)   
        self.build_button = GBuilder().pushbutton(parent, "Build Simulation", self._build_hit, os.getcwd() + r'/icons/build.png', 35, 35)
        self.build_button.setFixedHeight(40)
        vl_right.addWidget(self.build_button)
        
        # Table
        self.sims_table = GBuilder().table(parent, 5, 2, ["A"], False)
        self.sims_table.horizontalHeader().setResizeMode(1, QHeaderView.Fixed);
        self.sims_table.horizontalHeader().setResizeMode(0, QHeaderView.Stretch);
        self.sims_table.setColumnWidth(1, 32)
#         self.check_buts = GBuilder().add_checkbuttons(self.sims_table, 0, 1)

        self.sims_table.verticalHeader().setDefaultSectionSize(25)
        self.sims_table.verticalHeader().hide()    
        self.sims_table.horizontalHeader().hide()
        self.sims_table.setFixedHeight(110)
        
        vl_left.addWidget(self.sims_table)  
             
        hl_out.addLayout(vl_left) 
        hl_out.addLayout(vl_right)
        
    def _build_hit(self):
        self.build_window = BuildWindow(self)
        
    def _save_hit(self):
        self.save_window = SaveWindow(self)
               
    def _new_hit(self):
        self.new_window = NewSimulationWindow(self)
           
    def _import_hit(self):
        self.import_window = ImportWindow(self)
    
class NewSimulationWindow(QDialog):

    def __init__(self, parent):
        QDialog.__init__(self, parent)
        self.core = NewSimulationCore(self)
        self.create_widgets(parent)
        
        self.environments = []
        self.env_wid = {}  # Environment Name to Environment Widget
        self.env_obj = {}  # Environment Name to Environment Objects
        
        self.exec()
        
    def create_widgets(self, parent):
        
        # Layout
        GBuilder().set_props(self, min_sz_x=900, min_sz_y=700)
        self.setWindowTitle("Simulation Configuration")
        self.setFixedHeight(700)
        self.setFixedWidth(1350)
        main_lo = QVBoxLayout()
        self.setLayout(main_lo)

        # Label
        self.desc_label = GBuilder().label(self, "Create a new simulation. Create one or more environments and"\
                                           " fill them with components. Then connect the components.", None, None)
        self.desc_label.setFixedHeight(20)
        main_lo.addWidget(self.desc_label)
        
        # Horizontal Layout
        hl_1 = QHBoxLayout()
        main_lo.addLayout(hl_1)
        
        # Groupboxes
        self.components_gb = GBuilder().hand_groupbox(self, "Components", None, None)
        self.components_gb.setFixedWidth(300)
        self.environment_gb = GBuilder().groupbox(self, "Environments", None, None)
        hl_1.addWidget(self.components_gb)
        hl_1.addWidget(self.environment_gb)
        
        # Components Boxes
        self.comps_layout = QVBoxLayout()
        self.components_gb.setLayout(self.comps_layout)
        self._add_component_boxes()
               
        # Buttons
        main_lo.addWidget(GBuilder().hor_line(self))
        hl = QHBoxLayout()
        hl.addWidget(GBuilder().label(self, ""))
        ok_but = GBuilder().pushbutton(self, "OK", self._ok_hit)
        ok_but.setFixedWidth(150)
        ok_but.setFixedHeight(25)
        cancel_but = GBuilder().pushbutton(self, "Cancel", self._ok_hit)
        cancel_but.setFixedWidth(150)
        cancel_but.setFixedHeight(25)
        hl.addWidget(ok_but)
        hl.addWidget(cancel_but)
        main_lo.addLayout(hl)
        
        # Fill Components Boxes
        self._fill_ecu_boxes()
        self._fill_bus_boxes()
        self._fill_others_boxes()
        
        # Fill environment
        self._fill_environment_box()
        
        # Style 
        self._set_stle()
 
    def _add_component_boxes(self):
        
        # ECU Box
        self.ecu_box_wid = QScrollArea()
        wid = QWidget()
        self.ecu_box_wid.setWidget(wid)        
        self.ecu_box_wid.setWidgetResizable(True)               
        self.ecu_box = QGridLayout()
        wid.setLayout(self.ecu_box)   
        self.ecu_box_wid_wid = wid     
        self.comps_layout.addWidget(self.ecu_box_wid)

        # Bus Box
        self.bus_box_wid = QScrollArea()
        wid = QWidget()
        self.bus_box_wid.setWidget(wid)        
        self.bus_box_wid.setWidgetResizable(True)             
        self.bus_box = QGridLayout()
        wid.setLayout(self.bus_box)    
        self.bus_box_wid_wid = wid      
        self.comps_layout.addWidget(self.bus_box_wid)

        # Others Box
        self.others_box_wid = QScrollArea()
        wid = QWidget()
        self.others_box_wid.setWidget(wid)        
        self.others_box_wid.setWidgetResizable(True)       
        self.others_box = QGridLayout()
        wid.setLayout(self.others_box)
        self.others_box_wid_wid = wid  
        self.comps_layout.addWidget(self.others_box_wid)

    def _fill_ecu_boxes(self):
        
        # Creatable Objects
        kys = ECUFactory().createable_objects()   
        row = 0
        col = 0
        
        for ky in list(kys):                
            
            # Information gathering
            name = self._load_gui_name(ky, ECUFactory())  
            ico = self._load_gui_icon(ky, ECUFactory())                     
            
            # New Element per Object
            gb = GBuilder().groupbox(self, name, None, None)
            gb.setFont(QtGui.QFont('SansSerif', 7))
            gb.setFixedHeight(70)
            gb.setFixedWidth(70)            
            db = GBuilder().dragbutton(gb, '', self._add_component_boxes, ico, icon_x=45, icon_y=45, size_x=60, size_y=50, pos_x=5, pos_y=15)
            db.set_drop_func(self.core.add_ecu_box_to_env)
            db.set_move_icon_context_acts(self.core.load_context_menu_actions(ky))
            db.ecu_key = ky
            db.setCheckable(True)                
            db.setStyleSheet('QPushButton {background-color: #F2F2F2; color: red;border: 0px solid gray;border-radius: 12px;}')
            
            # Add to Layout
            self.ecu_box.addWidget(gb, row, col, Qt.AlignTop)            
            col += 1
            if col == 3:
                row += 1
                col = 0
                
        # Add Widget        
        self.ecu_box.addWidget(QWidget())
        
    def _fill_bus_boxes(self):
        
        kys = BusFactory().createable_objects()          
        
        row = 0
        col = 0
        
        for ky in list(kys):
            
            # Information gathering
            name = self._load_gui_name(ky, BusFactory())  
            ico = self._load_gui_icon(ky, BusFactory())                        
            
            # New Element per Object
            gb = GBuilder().groupbox(self, name, None, None)
            gb.setFont(QtGui.QFont('SansSerif', 7))
            gb.setFixedHeight(70)
            gb.setFixedWidth(70)            
            db = GBuilder().dragbutton(gb, '', self._add_component_boxes, ico, icon_x=45, icon_y=45, size_x=60, size_y=50, pos_x=5, pos_y=15)
            db.set_drop_func(self.core.add_bus_box_to_env)
            db.set_move_icon_context_acts(self.core.load_context_menu_actions(ky))
            db.ecu_key = ky
            db.setCheckable(True)
            db.setStyleSheet('QPushButton {background-color: #F2F2F2; color: red;border: 0px solid gray;border-radius: 12px;}')
            
            # Add to Layout
            self.bus_box.addWidget(gb, row, col, Qt.AlignTop)            
            col += 1
            if col == 3:
                row += 1
                col = 0
                
        # Add Widget        
        self.bus_box.addWidget(QWidget())
        
    def _fill_others_boxes(self):
        kys = ECUFactory().createable_objects()          
        
        row = 0
        col = 0

    def _fill_environment_box(self):
        
        # Main Layout
        main_lo = QVBoxLayout()        
        self.environment_gb.setLayout(main_lo)
                
        # Combobox
        lo, self.env_select_cb, lab = GBuilder().label_combobox(self, "Current Environment:", [], self._env_select_changed)
        hl = QHBoxLayout()
        hl.addLayout(lo)
        but = GBuilder().pushbutton(self, "New", self._new_env_hit)
        but.setFixedWidth(40)
        hl.addWidget(but)        
        lab.setFixedWidth(140)
        self.env_select_cb.setFixedHeight(22)  
        self.env_select_cb.setFixedWidth(350)      
        main_lo.addLayout(hl)
        
        # Groupbox (to make it look nicer)
        self.content_gb = EnvironmentView(self.environment_gb)    
        main_lo.addWidget(self.content_gb)
        self.content_gb.setFixedHeight(550)  
        self.content_gb.setFixedWidth(1000)  
        self.content_gb.setLayout(lo)
        
        # QStackedWidget with environments
        self.stacked_env = QStackedWidget()
        lo.addWidget(self.stacked_env)
       

    def _set_stle(self):
        
        self.content_gb.setStyleSheet('QGroupBox {background-color: #F2F2F2; color: red; border: 2px solid gray;border-radius: 12px;} EnvironmentView {background-color: #F2F2F2; color: red; border: 2px solid gray;border-radius: 12px;}')

        self.ecu_box_wid_wid.setStyleSheet('QWidget { border: 0.5px solid gray;border-radius: 3px;}')
        self.ecu_box_wid.setStyleSheet('QWidget { border: 0.5px solid gray;border-radius: 3px;}')
         
        self.bus_box_wid_wid.setStyleSheet('QWidget { border: 0.5px solid gray;border-radius: 3px;}')
        self.bus_box_wid.setStyleSheet('QWidget { border: 0.5px solid gray;border-radius: 3px;}')
         
        self.others_box_wid_wid.setStyleSheet('QWidget { border: 0.5px solid gray;border-radius: 3px;}')
        self.others_box_wid.setStyleSheet('QWidget { border: 0.5px solid gray;border-radius: 3px;}')
        
    def _ok_hit(self):
        
        # 1. Create environments using defined processing methods
        environments_list = NewSimulationCore().run_processes()        
        
        # 2. Save environments via API / Load them via API as well

        self.close()
        
    def _cancel_hit(self):
        print("Cancel")
        self.close()
        
    def _new_env_hit(self):
        
        # Add to list
        nr = len(self.environments)
        self.environments.append("Environment %s" % nr)        
        self.env_select_cb.addItem(self.environments[-1])
        self.env_select_cb.setCurrentIndex(nr)
        
        # Create new Stacked widget entry
        wid = QWidget()
        self.stacked_env.addWidget(wid)
        self.env_wid["Environment %s" % nr] = wid
        
        lo = QVBoxLayout()

        wid.setLayout(lo)
        self.stacked_env.setCurrentIndex(nr)

    def _env_select_changed(self):
        idx = self.env_select_cb.currentIndex()        
        self.stacked_env.setCurrentIndex(idx)        
        NewSimulationCore().selected_env = self.env_select_cb.currentText()
        self.content_gb.selected_env = self.env_select_cb.currentText()
        
        self._show_env(NewSimulationCore().selected_env, NewSimulationCore().env_map)
        
    def _get_env_elem_by_icon(self, env_elems, move_icon):        
        for elem in env_elems:            
            if str(elem.move_icon) == str(move_icon):
                return elem
        return None 
        
    def _load_gui_name(self, ky, factory):
        try:                                 
            cls = factory.get_class(ky)
            name = cls.GUI_NAME
        except:
            name = ky
        return name
    
    def _load_gui_icon(self, ky, factory):
        try:                                 
            cls = factory.get_class(ky)
            name = cls.GUI_ICON
        except:
            name = os.getcwd() + r'/icons/standard_ecu.png'
        return name

    def _show_env(self, selected_env, env_map):
        
        GBuilder().update_connected(self.content_gb, self.environment_gb.pos(), self.content_gb.pos(), self.content_gb.selected_env)
        
        # Mainwindow
        for chil in self.children():
            if isinstance(chil, DragLabel):
                try:
                    a = self._get_env_elem_by_icon(env_map[selected_env], chil)   
                    
                    if a == None:
                        chil.hide()
                    else:
                        chil.show()
                except:
                    chil.hide()
        
class ImportWindow(QDialog):
    
    def __init__(self, parent):
        QDialog.__init__(self, parent)
        self.create_widgets(parent)
        self.exec()
        
    def create_widgets(self, parent):
        pass
    
class SaveWindow(QDialog):
    
    def __init__(self, parent):
        QDialog.__init__(self, parent)
        self.create_widgets(parent)
        self.exec()
        
    def create_widgets(self, parent):
        pass
    
class BuildWindow(QDialog):
    
    def __init__(self, parent):
        QDialog.__init__(self, parent)
        self.create_widgets(parent)
        self.exec()
        
    def create_widgets(self, parent):
        pass
        
class AbstractAddPlugin(QWidget):
    ''' this class returns the widget that will be used
        to create a Component that will be added to the environment '''
    
    def __init__(self, parent):
        QWidget.__init__(self, parent)
    
    def set_gui(self, mapp):
        ''' set the gui from the map received '''
        raise NotImplementedError("set_gui not implemented ")
    
    def get_actions(self):
        return
                
    def get_map(self):
        ''' returns the map that is later used to set this plugin GUI 
            again and that is used to run the processors'''
        raise NotImplementedError("get_map not implemented ")
    
    def preprocess(self, env, mapp):
        ''' Will be called first for each plugin'''
        raise NotImplementedError("preprocess not implemented ")
        
    def main_process(self, env, mapp):
        ''' Will be called in the middle for each plugin'''
        raise NotImplementedError("main_process not implemented ")
        
    def postprocess(self, env, mapp):
        ''' Will be called in the end for each plugin'''
        raise NotImplementedError("postprocess not implemented ")
    
        
'''===============================================================================
    Implementation Part
==============================================================================='''       

        
class NewSimulationCore(Singleton):
    
    def __init__(self, gui_con):
        self.gui = gui_con
        
        self.selected_env = None
        self.env_map = {}  # Connects a environment Name to a list of EnvironmentElements
        
    def add_bus_box_to_env(self, cur_pos, bus_type, move_icon):
        
        if not self._handle_no_selection(move_icon): return

        # Load config from Element
        try:      
            # New Element
            move_icon.env_view = self.gui.content_gb
            cur_env_elems = self.env_map[self.selected_env]
            env_elem = self._get_env_elem_by_icon(cur_env_elems, move_icon)
            
            add_ecu = AddSingleBUSDialog(self.gui, bus_type, env_elem.processor, env_elem.gui_map)
        except:
            # Edit Element
            env_elem = EnvironmentElement(move_icon, bus_type)
            self._dict_add_two(self.env_map, self.selected_env, env_elem)
            add_ecu = AddSingleBUSDialog(self.gui, bus_type, None)
          
        # Save config  
        env_elem.processor = add_ecu.processor
        env_elem.comp_type = bus_type 
        env_elem.draws_line = True
        env_elem.gui_map = add_ecu.processor.get_map()

        
    def add_ecu_box_to_env(self, cur_pos, ecu_type, move_icon):
        
        # No environment selected
        if not self._handle_no_selection(move_icon): return
                  
        # Load config from Element
        try:      
            # New Element
            move_icon.env_view = self.gui.content_gb
            cur_env_elems = self.env_map[self.selected_env]
            env_elem = self._get_env_elem_by_icon(cur_env_elems, move_icon)   
            add_ecu = AddSingleECUDialog(self.gui, ecu_type, env_elem.processor, env_elem.gui_map)
            env_elem.processor = add_ecu.processor
            env_elem.comp_type = ecu_type 
        except:
            # Edit Element
            env_elem = EnvironmentElement(move_icon, ecu_type)
            self._dict_add_two(self.env_map, self.selected_env, env_elem)
            add_ecu = AddSingleECUDialog(self.gui, ecu_type, None)
            env_elem.processor = add_ecu.processor
            env_elem.comp_type = ecu_type 
        
        # Save config
        env_elem.gui_map = add_ecu.processor.get_map()
        
    def run_processes(self):
        ''' run all processes (pre, main, post) and create 
            a environment from that '''
        res_envs = []
        for env_name in self.env_map:
            new_env = api.ecu_sim_api.create_environment(2000)            
            self._run_process(new_env, env_name)
            res_envs.append(new_env)
        return res_envs
           
    def load_context_menu_actions(self, ecu_type):
        ''' load the context menu actions for the specific
            ecu type'''
        try:
            act = QtGui.QAction(QtGui.QIcon(os.getcwd() + r'/icons/p.png'), "Connect", self.gui)              
            act.setStatusTip("Connect the selected items")
            act.triggered.connect(self._connect)  
            return [act]
        except:
            return []             
    def _handle_no_selection(self, move_icon):
        if self.selected_env == None:
            q = QMessageBox(QMessageBox.Warning, "Warning", "Element could not be added. No environment selected.")
            q.exec(); 
            move_icon.setParent(None);
            return False
        return True
             
    def _connect(self):
        ''' connect two items'''
                
        # open Connect window,
        self._cur_selected_connection = None
        self.dia = QDialog(self.gui); main_lo = QVBoxLayout()        
        GBuilder().set_props(self.dia, None, 250, 130, max_sz_x=400, max_sz_y=250)
        try:
            self.selected_env_elems = EnvironmentElement.icons_to_env_els(DragSelection().selected, self.env_map[self.selected_env])
            self.clicked_elem = EnvironmentElement.icons_to_env_els([DragSelection().clicked], self.env_map[self.selected_env])[0]
            self.selected_env_elems.remove(self.clicked_elem)
        except:
            return
        
        # show possible connections
        if not self.selected_env_elems: return
        acts = self.clicked_elem.processor.get_actions()
        main_lo.addWidget(GBuilder().label(self.dia, "Select a connection to be executed between type %s and type %s" % (self.clicked_elem.comp_type, self.selected_env_elems[0].comp_type)))
        hl, self._con_cb, te = GBuilder().label_combobox(self.dia, "Select Connection ", list(acts.values()), self.dia.show)
        main_lo.addLayout(hl)
        
        # ok cancel
        main_lo.addWidget(GBuilder().hor_line(self.dia))
        ok = GBuilder().pushbutton(self.dia, "Apply", self._ok_dia_hit); ok.setFixedWidth(100)
        canc = GBuilder().pushbutton(self.dia, "Cancel", self._cancel_dia_hit); canc.setFixedWidth(100)
        
        hl = QHBoxLayout() 
        hl.addWidget(GBuilder().label(self.dia, ""))
        hl.addWidget(ok)
        hl.addWidget(canc)
        main_lo.addLayout(hl)
        
        self.dia.setLayout(main_lo)
        self.dia.exec()
        
    def _ok_dia_hit(self): 
        
        # if can connected to ecu, draw a line
        if self.clicked_elem.draws_line:
            self._draw_lines(self.clicked_elem, self.selected_env_elems)
        
        # Apply selected connection
        self._clear_selected()
        new_con = EnvironmentConnection(self.clicked_elem, self.selected_env_elems, self._con_cb.currentText())                
        self.clicked_elem.add_connection(new_con)
        self.dia.close()
        
    def _cancel_dia_hit(self):
        self._clear_selected()
        self.dia.close()
      
    def _clear_selected(self):
        
        for lab in DragSelection().selected:
            lab.setStyleSheet('QLabel {border: 0px solid red;border-radius: 15px;}')
        
        DragSelection().clicked = []
        DragSelection().selected = []
                
    def _draw_lines(self, prime_env_el, connected_env_els):        
        
        try:
            DragSelection().connected[self.selected_env]
        except:
            DragSelection().connected[self.selected_env] = []
        
        DragSelection().connected[self.selected_env].append(LineConnection(prime_env_el.move_icon, [o.move_icon for o in connected_env_els]))
        GBuilder().update_connected(self.gui.content_gb, self.gui.environment_gb.pos(), self.gui.content_gb.pos(), self.selected_env)
    

    
    def _run_process(self, my_env, env_name):
        procs = []
        
        # Run all processors
        for cur_elem in self.env_map[env_name]:
            gui_map = cur_elem.gui_map  # possibly unnecessary            
            processor = cur_elem.processor
            procs.append(processor)
            
        # pre processes 
        for proc in procs:
            proc.preprocess(my_env, gui_map)
            
        # main processes
        for proc in procs:
            proc.main_process(my_env, gui_map)
            
        # Post processes
        for proc in procs:
            proc.postprocess(my_env, gui_map)

    def _get_env_elem_by_icon(self, env_elems, move_icon):
        for elem in env_elems:            
            if str(elem.move_icon) == str(move_icon):
                return elem
        return None

    def _dict_add_two(self, dic, ky1, val):
        try:
            dic[ky1] 
        except:
            dic[ky1] = []        
        dic[ky1].append(val)

class EnvironmentConnection(object):
    
    def __init__(self, elem_1, lst_elems_2, act_type):
        ''' elem_1 is the object invoking a method in connection
            with all objects in list elems_2'''
        self.exec_elem = elem_1
        self.execed_elems = lst_elems_2
        self.act_type = act_type
    
        
class EnvironmentElement(object):
    ''' This is a gui element that is visible
        in the Add Window '''
    GLOB_CNT = 0
    
    def __init__(self, move_icon, ecu_type):
                
        self.processor = None  # Processor
        self.gui_map = {}  # Content of this gui element
        self.connections = []  # Connections to other gui Elements
        self.element_id = EnvironmentElement.GLOB_CNT
        self.comp_type = ecu_type 
        self.move_icon = move_icon
        EnvironmentElement.GLOB_CNT += 1
        
        self.draws_line = False
        
        self.move_icon.setToolTip("ID: %s_%s\n" % (self.comp_type, str(self.element_id)))
        
    def add_connection(self, connection):
        self.connections.append(connection)        
        self.move_icon.setToolTip(self._connections_2_str())
        
    def _connections_2_str(self):
        res_str = "ID: %s_%s\n" % (self.comp_type, str(self.element_id))
        res_str += "Connections:"
        for con in self.connections:
#             el_1 = con.exec_elem.comp_type + "_" + str(con.exec_elem.element_id)
            el_2 = ""
            for el in con.execed_elems:
                el_2 += "\t - " + el.comp_type + "_" + str(el.element_id) + "\n"
            res_str += "\nType: %s\n" % con.act_type
#             res_str += el_1
            res_str += el_2
        return res_str
            
    @staticmethod        
    def icons_to_env_els(lst_icons, lst_env_els):
        els = []
        
        for ico in lst_icons:
            for el in lst_env_els:
                if str(ico) == str(el.move_icon):
                    els.append(el)
                    break
        return els

         
class AddSingleBUSDialog(QDialog):

    def __init__(self, parent, bus_type, processor, mapp=False):
        QDialog.__init__(self, parent)
        self.bus_type = bus_type
        self.processor = processor
        self.setWindowTitle("Add Component")
        self.map = {}  # Saves the values of the GUI
        if mapp:
            self.map = mapp
            self.create_widgets(parent, self.map)
        else:
            self.create_widgets(parent)
        self.exec()

    def create_widgets(self, parent, mapp=False):    
        
        # Layout
        GBuilder().set_props(self, min_sz_x=500, min_sz_y=150)
        main_lo = QVBoxLayout()
        self.setLayout(main_lo)

        # Get Add Dialog
        try:
            
            # Read API Spec that I need
            cls = BusFactory().get_class(self.bus_type)
            self.processor = cls.get_add_plugin(parent)
            if mapp:
                self.processor.set_gui(mapp)
            main_lo.addWidget(self.processor)
        except:
            print(traceback.format_exc())
            ECULogger().log_traceback()
        
        # Ok and Cancel
        main_lo.addWidget(GBuilder().hor_line(parent))
        hl = QHBoxLayout() 
        hl.addWidget(GBuilder().label(parent, ""))
        ok = GBuilder().pushbutton(parent, "OK", self._ok_hit)
        ok.setFixedWidth(100)
        hl.addWidget(ok)
        canc = GBuilder().pushbutton(parent, "Cancel", self._cancel_hit)
        canc.setFixedWidth(100)
        hl.addWidget(canc)
        main_lo.addLayout(hl)
            
    def _ok_hit(self):
        self.map = self.processor.get_map()        
        self.close()
    
    def _cancel_hit(self):
        print("Cancel")
        self.close()
         
class AddSingleECUDialog(QDialog):

    def __init__(self, parent, ecu_type, processor, mapp=False):
        QDialog.__init__(self, parent)
        self.ecu_type = ecu_type
        self.processor = processor
        self.setWindowTitle("Add Component")
        self.map = {}  # Saves the values of the GUI
        if mapp:
            self.map = mapp
            self.create_widgets(parent, self.map)
        else:
            self.create_widgets(parent)
        self.exec()

    def create_widgets(self, parent, mapp=False):    
        
        # Layout
        GBuilder().set_props(self, min_sz_x=500, min_sz_y=150)
        main_lo = QVBoxLayout()
        self.setLayout(main_lo)

        # Get Add Dialog
        try:
            
            # Read API Spec that I need
            cls = ECUFactory().get_class(self.ecu_type)
            self.processor = cls.get_add_plugin(parent)
            if mapp:
                self.processor.set_gui(mapp)
            main_lo.addWidget(self.processor)
        except:
            print(traceback.format_exc())
            ECULogger().log_traceback()
        
        # Ok and Cancel
        main_lo.addWidget(GBuilder().hor_line(parent))
        hl = QHBoxLayout() 
        hl.addWidget(GBuilder().label(parent, ""))
        ok = GBuilder().pushbutton(parent, "OK", self._ok_hit)
        ok.setFixedWidth(100)
        hl.addWidget(ok)
        canc = GBuilder().pushbutton(parent, "Cancel", self._cancel_hit)
        canc.setFixedWidth(100)
        hl.addWidget(canc)
        main_lo.addLayout(hl)
            
    def _ok_hit(self):
        self.map = self.processor.get_map()        
        self.close()
    
    def _cancel_hit(self):
        print("Cancel")
        self.close()
        

