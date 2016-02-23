from gui.gui_builder import GBuilder, GEnums, try_ex
import os
from gui.plugins.widget_factories import ViewerPluginFactory
from PyQt4.Qt import QVBoxLayout, QHBoxLayout, QThread, QWidget

import api.ecu_sim_api as api 
from PyQt4 import QtGui, QtCore
import sys
import threading
import pickle
from tools.ecu_logging import ECULogger
from math import ceil
import logging


__title__ = "Automotive Networks Simulator"
__version__ = "0.1"
__author__ = "Artur Mrowca"
__enterprise__ = "TUM Create Limited"
__departement__ = "RP3 - Embedded Systems"

class DirectViewer(object):
      
    @try_ex
    def run(self, reader, view_plugs, lock=False):     
        ''' runs the app in a new thread'''   
        self.t = threading.Thread(target=self._run, args=(reader, view_plugs, lock))
        self.t.setDaemon(True)
        self.t.start()
     
    @try_ex       
    def show(self, reader, view_plugs, q_app):  
        ''' runs the app in the same thread'''     
        try:
            if not q_app:
                run_it = False
                self.q_app = QtGui.QApplication(sys.argv)
            else:
                run_it = True
                self.q_app = q_app     
            view_plug_imp = []
            for plug in view_plugs:
                view = ViewerPluginFactory().make(plug)
                view.set_reader(reader)        
                view_plug_imp.append(view)
    
            self.gui = DirectViewWindow(view_plug_imp)
            self.gui.link_axis()
            self.gui.show()        
            
            if not run_it:
                sys.exit(self.q_app.exec_())
        except SystemExit:
            print("Qt Window Thread finalized")
            self.gui.close()
           
    @try_ex     
    def _run(self, reader, view_plugs, lock=False):       
        try:
            self.q_app = QtGui.QApplication(sys.argv)        
            view_plug_imp = []
            for plug in view_plugs:
                view = ViewerPluginFactory().make(plug)
                view.set_reader(reader)        
                view_plug_imp.append(view)
    
            self.gui = DirectViewWindow(view_plug_imp)
            self.gui.link_axis()
            self.gui.show()        
            
            if lock:
                lock.release()
            
            sys.exit(self.q_app.exec_())
        except SystemExit:
            print("Qt Window Thread finalized")
            self.gui.close()
        
    def load_show(self, view_plugs, filepath=False):
        # if no filepath given can select it
        self.q_app = QtGui.QApplication(sys.argv)
        
        view_plug_imp = []
        for plug in view_plugs:
            view = ViewerPluginFactory().make(plug)
            view_plug_imp.append(view)
        
        self.gui = DirectViewWindow(view_plug_imp)
        self.gui.show()
        
        if filepath:
            self.gui._load_views_hit(filepath)
        
        sys.exit(self.q_app.exec_())
        
class DirectViewWindow(QtGui.QMainWindow):
    '''
    View Window that can be connected to a simulation
    '''
    def __init__(self, views, *args, **kwargs):
        QtGui.QMainWindow.__init__(self, *args, **kwargs)
        
        ''' 1. members '''
        self.builder = GBuilder()       

        ''' 2. initialize the gui factories '''
        self.view_plugins = views
        
        ''' 3. actions '''
        self.init_actions()
        self.create_widgets()
    
    @try_ex          
    def create_widgets(self):
        
        ''' 1. Main window '''
        self.setWindowTitle('TUMCreate - Automotive Simulator - Direct View')
        self.setWindowIcon(QtGui.QIcon(os.path.join(os.path.dirname(__file__), r'../icons/tumcreatelogo2.png')))
        self.builder.set_props(self, ctr_lout=True, min_sz_x=1200, min_sz_y=700)

        ''' 2. Two Group Boxes '''              
        self.groupb_info = self.builder.groupbox(self, 'Information', max_height=200, max_width=2000) 
        self.set_info_group()
        
        self.groupb_viewer = self.builder.groupbox(self, 'View')
        self.set_viewer_group()
        
        ''' 3. Init Menubar '''
        self.init_menubar();            
                
        ''' 4. Toolbar'''
        self.toolbar_gen_sets = self.builder.toolbar(self, GEnums.T_TOP, actions=self.gen_set_actions)
        
        ''' 5. Create Layout'''
        self.init_layout()
    
    @try_ex
    def init_actions(self):
        
        ''' 1. Create General Settings'''   

        self.exit_action = QtGui.QAction(QtGui.QIcon(os.path.join(os.path.dirname(__file__), r'../icons/exit.png')), '&Exit', self)        
        self.exit_action.setShortcut('Ctrl+Q')
        self.exit_action.setStatusTip('Exit application')
        self.exit_action.triggered.connect(QtGui.qApp.quit)
        
        self.help_action = QtGui.QAction(QtGui.QIcon(os.path.join(os.path.dirname(__file__), r'../icons/help.png')), '&Help', self)        
        self.help_action.setShortcut('F3')
        self.help_action.setStatusTip('Open Help')
        self.help_action.triggered.connect(QtGui.qApp.quit)
               
        self.clear_action = QtGui.QAction(QtGui.QIcon(os.path.join(os.path.dirname(__file__), r'../icons/clear.png')), '&Clear all parameters', self)        
        self.clear_action.setShortcut('Ctrl+Shift+N')
        self.clear_action.setStatusTip('Open Help')
        self.clear_action.triggered.connect(QtGui.qApp.quit) 
        
        self.load_action = QtGui.QAction(QtGui.QIcon(os.path.join(os.path.dirname(__file__), r'../icons/load.png')), '&Clear all parameters', self)        
        self.load_action.setShortcut('Ctrl+Shift+L')
        self.load_action.setStatusTip('Load file')
        self.load_action.triggered.connect(self._load_views_hit) 
        
        ''' 2. define all actions that will appear in the general Toolbar '''
        self.gen_set_actions = [self.clear_action, self.help_action, self.load_action]
    
    @try_ex
    def init_layout(self):
        ''' Sets the layout for the three main groupboxes '''
        
        main_layout = self.centralWidget().layout()
        
        h_layout = QtGui.QHBoxLayout()
        
        h_layout.addWidget(self.groupb_info)        
        
        main_layout.addLayout(h_layout)
        
        main_layout.addWidget(self.groupb_viewer)
         
    @try_ex
    def init_menubar(self):
        
        ''' 1. Create Menubar'''
        menubar = self.menuBar()
        
        ''' 2. add Menus and actions'''        
        # File
        file_menu = menubar.addMenu('&File')
        file_menu.addAction(self.exit_action)
                
        # Help        
        help_menu = menubar.addMenu('&Help')
        help_menu.addAction(self.help_action)
        
    def link_axis(self):   
        link_plot = False     
        for view in self.view_plugins:
            # check if there are link axis
            p = view.link_axis()
            if p != None:
                if link_plot:
                    p.setXLink(link_plot)
                else:
                    link_plot = p
        
    @try_ex
    def set_cb_changed_event_set(self):
        self.settings_stack.setCurrentIndex(self.settings_cbox.currentIndex())

    @try_ex
    def set_info_group(self):

        ''' 1. Logo'''
        self.space = QtGui.QLabel()
        self.info_label = QtGui.QLabel("\nTitle:          \t%s \nAuthor:          \t%s\nCompany:\t%s\nDepartement:\t%s\nVersion:          \t%s" % (__title__, __author__, __enterprise__, __departement__ , __version__))
        self.space.setFixedWidth(10)
        
        self.info_logo = self.builder.image(self.groupb_info, os.path.dirname(__file__)[:-4] + r'/icons/tumcreatelogo.png', 2.4)
        self.info_logo.setMaximumWidth(270)
        
        ''' 2. Description Text '''
        self.desc_txt = self.builder.label(self.groupb_info, "<b>Description:    </b>" + '\n\nThis application simulates an automotive environment. It offers the possibility to perform timing analyses of communication flows between a certain number of ECUs.')
                   
        ''' 3. Groupbox Layout'''
        v_layout = QtGui.QVBoxLayout(self.groupb_info)  
                      
        h_layout_one = QtGui.QHBoxLayout()
        h_layout_one.addWidget(self.space)
        h_layout_one.addWidget(self.info_label)        
        h_layout_one.addWidget(self.info_logo)

        v_layout.addLayout(h_layout_one)
        v_layout.addWidget(self.desc_txt)
    
    @try_ex
    def set_cb_changed_event_view(self, e):
        # check which items are selected and show all of them
        try:
            # clear all
            try:
                for ky in self.wid_to_idx:
                    self.wid_to_idx[ky].setParent(None)                
            except:
                ECULogger().log_traceback()
            
            # get checked items
            checked_idx = []
            for cnt in range(self.viewer_cbox.count()):
                item = self.viewer_cbox.model().item(cnt, 0)
                if item.checkState():                
                    checked_idx.append(cnt)
            
            row_nr = int(self.arrange_rows.text())
            col_nr = int(self.arrange_cols.text())
            
            if row_nr * col_nr < len(checked_idx):
                row_nr = ceil(float(len(checked_idx)) / col_nr) 
                self.arrange_rows.setText(str(row_nr))
            # arrange
            cnt = 0
            for r in range(row_nr):            
                hlay = QHBoxLayout()
                for c in range(col_nr):
                    try:
                        wid = self.wid_to_idx[checked_idx[cnt]]; cnt += 1
                        hlay.addWidget(wid)
                    except:
                        pass
                try:
                    self.main_v_layout.addLayout(hlay)
                except:
                    pass
        except:
            pass

    @try_ex
    def set_viewer_group(self):
        
        ''' 1. Load Items from viewer factory '''
        self.wid_to_idx = {}
        self.viewer_cbox = self.builder.checkable_combobox(self.groupb_viewer, [], self.set_cb_changed_event_view)
        self.save_but = self.builder.pushbutton(self.groupb_viewer, "Save", self._save_hit)
        self.save_but.setFixedWidth(100)
        
        # field to enter arrangement
        [lay_r, self.arrange_rows] = self.builder.label_text(self.groupb_viewer, "rows:", 25, 40, self.set_cb_changed_event_view)
        self.arrange_rows.setText('2')
        [lay_c, self.arrange_cols] = self.builder.label_text(self.groupb_viewer, "columns:", 40, 40, self.set_cb_changed_event_view)
        self.arrange_cols.setText('2')
        
        cnt = 0
        for view in self.view_plugins:            
            if view != None:
                self.viewer_cbox.addItem(view.get_combobox_name())
                item = self.viewer_cbox.model().item(cnt, 0)
                item.setCheckState(QtCore.Qt.Checked)
                self.wid_to_idx[cnt] = view.get_widget(self)
                cnt += 1

        ''' Layout '''
        self.main_v_layout = QVBoxLayout()
        self.viewer_cbox.setFixedHeight(25)       
        
        hl = QHBoxLayout()
        hl.addWidget(self.viewer_cbox)   
        hl.addLayout(lay_r)
        hl.addLayout(lay_c)     
        hl.addWidget(self.save_but)
        self.main_v_layout.addLayout(hl)           
              
        self.groupb_viewer.setLayout(self.main_v_layout)       
    
        self.set_cb_changed_event_view(None)
    
    def _load_views_hit(self, filename=False):
        
        if not filename:
            filename = QtGui.QFileDialog.getOpenFileName(self, 'Load', '', 'Simulation (*.tum)')
        with open(filename, 'rb') as f:
            save_vals = pickle.load(f)
        
        for view in self.view_plugins:  
            if view != None:
                try:
                    save_val = save_vals[view.get_combobox_name()]
                except:
                    logging.warn("Warning: On GUI load no saved values found for %s" % view.__class__.__name__)
#                     ECULogger().log_traceback()
                    continue
                view.load(save_val)

    def _save_hit(self):
        
        save_vals = {}
        
        for view in self.view_plugins:  
            if view != None:
                try:
                    print("Call save on %s" % view)
                    save_val = view.save()
                    print("OK!")
                except:
                    ECULogger().log_traceback()
                    continue
                save_vals[view.get_combobox_name()] = save_val
        
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "", ".tum")
        with open(filename, 'wb') as f:          
            pickle.dump(save_vals, f, pickle.HIGHEST_PROTOCOL)
                            
class SimulationThread(QThread):
    
    def __init__(self, parent, env):
        QThread.__init__(self, parent)        
        self.env = env    
    
    @try_ex
    def run(self):
        api.run_simulation(self.env)
