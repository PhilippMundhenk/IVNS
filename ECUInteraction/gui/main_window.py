import logging
import os

from PyQt4 import QtGui
from PyQt4.Qt import QVBoxLayout, QHBoxLayout, QThread

from api.core.api_core import APICore, TimingFunctionSet
from api.core.component_specs import SimpleECUSpec, SimpleBusSpec
import api.ecu_sim_api as api
from components.base.message.abst_bus_message import AbstractBusMessage
from components.security.communication.stream import MessageStream
from components.security.ecu.types.impl_ecu_secure import StdSecurECUTimingFunctions
from components.security.ecu.types.impl_sec_mod_lwa import StdSecurLwSecModTimingFunctions
from components.security.encryption.encryption_tools import EncryptionSize
from enums.sec_cfg_enum import CAEnum, HashMechEnum, AsymAuthMechEnum, \
    AuKeyLengthEnum, SymAuthMechEnum
from gui.gui_builder import GBuilder, GEnums
from gui.plugins.widget_factories import SettingsPluginFactory, \
    ViewerPluginFactory
from io_processing.surveillance import Monitor



__title__ = "Automotive Networks Simulator"
__version__ = "1.0"
__author__ = "Artur Mrowca"
__enterprise__ = "TUM Create Limited"
__departement__ = "RP3 - Embedded Systems"


class MainWindow(QtGui.QMainWindow):
    '''
    Main Window of the application
    '''
    def __init__(self, *args, **kwargs):
        QtGui.QMainWindow.__init__(self, *args, **kwargs)
        
        ''' 1. members '''
        self.builder = GBuilder()
        self.monitor = Monitor()
        self.setWindowTitle('TUMCreate - Automotive Simulator')
        self.setWindowIcon(QtGui.QIcon(os.path.join(os.path.dirname(__file__), r'../icons/tumcreatelogo2.png')))
        
        ''' 2. initialize the gui factories '''
        ViewerPluginFactory().load_classes()
        SettingsPluginFactory().load_classes()
        
        ''' 3. actions '''
        self.init_actions()
        self.create_widgets()
              
    def create_widgets(self):
        
        ''' 1. Main window '''
        self.builder.set_props(self, ctr_lout=True, min_sz_x=1200, min_sz_y=700)
        
        ''' 2. Three Group Boxes '''
        self.groupb_settings = self.builder.groupbox(self, 'Settings', max_height=200)
        self.set_settings_group()
              
        self.groupb_info = self.builder.groupbox(self, 'Information', max_height=200, max_width=700) 
        self.set_info_group()
        
        self.groupb_viewer = self.builder.groupbox(self, 'View')
        self.set_viewer_group() 
        
        ''' 3. Init Menubar '''
        self.init_menubar();            
                
        ''' 4. Toolbar'''
        self.toolbar_gen_sets = self.builder.toolbar(self, GEnums.T_TOP, actions=self.gen_set_actions)

        ''' 5. Create Layout'''
        self.init_layout()
    
    def create_aut_env(self):  # Spaeter on Button Click z.B.
        ''' this method creates the simulation'''               
        
        api_log_path = os.path.join(os.path.dirname(__file__), "../logs/api.log")
        api.show_logging(logging.INFO, api_log_path, True)
        my_env = api.create_environment(2500)
        
        ecu_spec = SimpleECUSpec([], 200, 200)
        ecu_group_1 = api.set_ecus(my_env, 10, 'SecureECU', ecu_spec)
        
        ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 100)
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 1000)
        
        sec_mod_group = api.set_ecus(my_env, 1, 'SecLwAuthSecurityModule', ecu_spec)
        
        bus_spec = SimpleBusSpec(['CAN_0'])
        bus_group = api.set_busses(my_env, 1, 'StdCANBus', bus_spec)
        api.connect_bus_by_obj(my_env, 'CAN_0', ecu_group_1 + sec_mod_group)
        
        api.register_ecu_groups_to_secmod(my_env, sec_mod_group[0].ecu_id, [ecu_group_1])
        
        certeros = api.create_cert_manager()
        for ecu in APICore()._ecu_list_from_groups([[ecu_group_1]]):  # UNINTENDED HACK
            api.generate_valid_ecu_cert_cfg(certeros, ecu.ecu_id, CAEnum.CA_L313, 'SEC 1', 0, float('inf'))
        api.generate_valid_sec_mod_cert_cfg(certeros, 'SEC 1', CAEnum.CA_L313, 0, float('inf'))
        api.apply_certification(my_env, certeros)
        
        
        stream_1 = MessageStream(my_env.get_env(), 'SecureECU_0', ['SecureECU_1', 'SecureECU_4', 'SecureECU_5'], 13, float('inf'), 0, float('inf'))
        stream_2 = MessageStream(my_env.get_env(), 'SecureECU_1', ['SecureECU_3', 'SecureECU_2', 'SecureECU_5'], 12, float('inf'), 0, float('inf'))
        stream_3 = MessageStream(my_env.get_env(), 'SecureECU_0', ['SecureECU_4', 'SecureECU_1', 'SecureECU_5'], 222, float('inf'), 0, float('inf'))
        stream_4 = MessageStream(my_env.get_env(), 'SecureECU_3', ['SecureECU_0', 'SecureECU_1', 'SecureECU_5'], 11, float('inf'), 0, float('inf'))
        stream_5 = MessageStream(my_env.get_env(), 'SecureECU_4', ['SecureECU_2', 'SecureECU_1', 'SecureECU_3'], 500, float('inf'), 0, float('inf'))
        api.add_allowed_stream(my_env, 'SEC 1', stream_1)
        api.add_allowed_stream(my_env, 'SEC 1', stream_2)
        api.add_allowed_stream(my_env, 'SEC 1', stream_3)
        api.add_allowed_stream(my_env, 'SEC 1', stream_4)
        api.add_allowed_stream(my_env, 'SEC 1', stream_5)
        
        t_set = TimingFunctionSet()
        ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag='CyaSSL')
        t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
        api.apply_timing_functions_set(my_env, 'SEC 1', t_set)
          
        t_set2 = TimingFunctionSet() 
        ecu_func_set = StdSecurECUTimingFunctions(main_library_tag='CyaSSL')
        
        for ecu in APICore()._ecu_list_from_groups([[ecu_group_1]]):  # UNINTENDED HACK
            t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
            api.apply_timing_functions_set(my_env, ecu.ecu_id, t_set2)

        api.connect_monitor(my_env, self.monitor, 50)
        api.build_simulation(my_env)
        
        ''' start this in a new thread'''
        sim = SimulationThread(self, my_env)
        sim.start()
          
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
        
        ''' 2. define all actions that will appear in the general Toolbar '''
        self.gen_set_actions = [self.clear_action, self.help_action]

    def init_layout(self):
        ''' Sets the layout for the three main groupboxes '''
        
        main_layout = self.centralWidget().layout()
        
        h_layout = QtGui.QHBoxLayout()
        
        h_layout.addWidget(self.groupb_settings)
        h_layout.addWidget(self.groupb_info)        
        
        main_layout.addLayout(h_layout)
        main_layout.addWidget(self.groupb_viewer)
         
    def init_menubar(self):
        
        ''' 1. Create Menubar'''
        menubar = self.menuBar()
        
        ''' 2. add Menus and actions'''        
        # File
        file_menu = menubar.addMenu('&File')
        file_menu.addAction(self.clear_action)
        file_menu.addAction(self.exit_action)
                
        # Help        
        help_menu = menubar.addMenu('&Help')
        help_menu.addAction(self.help_action)
    
    def set_settings_group(self):
        
        ''' 1. Load Items from settings factory '''
        set_fact = SettingsPluginFactory()
        self.settings_stack = QtGui.QStackedWidget()
        
        self.settings_cbox = self.builder.combobox(self.groupb_settings, [], self.set_cb_changed_event_set)

        for setting_plugin in set_fact.createable_objects():
            setting = set_fact.make(setting_plugin)
            
            if setting != None:                                                       
                self.settings_stack.addWidget(setting.get_widget(self))
                self.settings_cbox.addItem(setting.get_combobox_name())                
                
        ''' layout '''
        v_layout = QVBoxLayout()
                
        self.settings_cbox.setFixedHeight(20)        
        v_layout.addWidget(self.settings_cbox) 
        v_layout.addWidget(self.settings_stack) 
    
        self.groupb_settings.setLayout(v_layout)
    
    def set_cb_changed_event_set(self):
        self.settings_stack.setCurrentIndex(self.settings_cbox.currentIndex())

    def set_info_group(self):

        ''' 1. Logo'''
        self.space = QtGui.QLabel()
        self.info_label = QtGui.QLabel("\nTitle:          \t%s \nAuthor:          \t%s\nCompany:\t%s\nDepartement:\t%s\nVersion:          \t%s" % (__title__, __author__, __enterprise__, __departement__ , __version__))
        self.space.setFixedWidth(10)
        
        self.info_logo = self.builder.image(self.groupb_info, os.path.join(os.path.dirname(__file__), r'../icons/tumcreatelogo.png', 2.4))
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

    def set_cb_changed_event_view(self):
        self.viewer_stack.setCurrentIndex(self.viewer_cbox.currentIndex())

    def set_viewer_group(self):
        
        ''' 1. Load Items from viewer factory '''
        view_fact = ViewerPluginFactory()
        self.viewer_stack = QtGui.QStackedWidget()        
        self.viewer_cbox = self.builder.combobox(self.groupb_viewer, [], self.set_cb_changed_event_view)
        self.set_start_button = self.builder.pushbutton(self.groupb_viewer, 'Start Simulation', self.create_aut_env)
        self.set_start_button.setFixedWidth(200)
        self.set_start_button.setFixedHeight(25)

        for viewer_plugin in view_fact.createable_objects():
            view = view_fact.make(viewer_plugin)
            if view != None:
                view.set_monitor(self.monitor)                 
                self.viewer_stack.addWidget(view.get_widget(self))
                self.viewer_cbox.addItem(view.get_combobox_name())                

        ''' layout '''
        v_layout = QVBoxLayout()                
        self.viewer_cbox.setFixedHeight(25)       
        v_layout.addWidget(self.viewer_stack)  
        
        hl = QHBoxLayout()
        hl.addWidget(self.viewer_cbox)
        hl.addWidget(self.set_start_button)
        v_layout.addLayout(hl)           
              
        self.groupb_viewer.setLayout(v_layout)    
    
class SimulationThread(QThread):
    
    def __init__(self, parent, env):
        QThread.__init__(self, parent)        
        self.env = env    
        
    def run(self):
        api.run_simulation(self.env)
