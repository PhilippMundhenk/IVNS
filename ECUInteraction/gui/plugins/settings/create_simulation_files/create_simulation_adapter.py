from gui.plugins.settings.create_simulation_impl import AbstractAddPlugin
import uuid
from tools.ecu_logging import ECULogger
import api
from api_core import SimpleECUSpec
from gui.gui_builder import GBuilder
from PyQt4.Qt import QVBoxLayout
from PyQt4.QtGui import QHBoxLayout
from components.security.ecu.types.impl_ecu_secure import SecureECU, \
    StdSecurECUTimingFunctions
from tools.singleton import Singleton
import os
from components.base.bus.impl_bus_can import StdCANBus
from components.security.ecu.types.impl_sec_mod_lwa import StdSecurLwSecModTimingFunctions, \
    SecLwAuthSecurityModule

class AddWidgetAdapter(Singleton):
    ''' This class connects the ECU classes to their respective
        GUI processing units'''
    
    def __init__(self):
        pass
    

class SecureECUAddWidget(AbstractAddPlugin):
    ''' This is the interface that connects the GUI and the actions to
        execute for a SecureECU when it is to be created in the new
        simulation window '''
    
    GUI_NAME = "ECU Secure"
    GUI_ICON = os.getcwd() + r'/icons/secure_ecu.png'

    def __init__(self, parent):
        AbstractAddPlugin.__init__(self, parent)        
        self._create_widgets(parent)
        self.parent = parent
                
        self.set_ecu_settings = {}
        self.set_time_lib = {}
        self.has_sec_mod_cert = False
        self.id = uuid.uuid4()
        
        self.ecu_group = None
        
    def set_gui(self, mapp):
        ''' set the gui from the map received '''
        try:
            if "id_list" in mapp: self.id_list.setText(str(mapp["id_list"]))
            if "send_buffer" in mapp: self.send_buf_textedit.setText(str(mapp["send_buffer"]))
            if "rec_buffer" in mapp: self.rec_buf_textedit.setText(str(mapp["rec_buffer"]))
            if "nr_ecus" in mapp: self.nr_ecus_textedit.setText(str(mapp["nr_ecus"]))
            
            if "ecu_settings" in mapp: self.set_ecu_settings = mapp["ecu_settings"]
            self._set_cb_changed()
            
            if "ecu_timing" in mapp: self.set_time_lib = mapp["ecu_timing"]
            index = self.ecu_set_time_sel_cb.findText(self.set_time_lib[self.ecu_set_time_cb.currentText()])
            self.ecu_set_time_sel_cb.setCurrentIndex(index)  
            self._cur_set_time_entry = self.ecu_set_time_cb.currentText()  
            
            if "has_sec_mod_cert" in mapp: self.has_sec_mod_cert = mapp["has_sec_mod_cert"]
            if not self.has_sec_mod_cert: self.has_sec_mod_cert_cb.setCurrentIndex(0)
            
        except:
            ECULogger().log_traceback()

    def get_map(self):
        
        
        mapping_values = {}
        # Read the values from the gui and save them  
        # General Information      
        mapping_values["id_list"] = self._wrap(eval, self.id_list.text(), [])
        mapping_values["send_buffer"] = self._wrap(int, self.send_buf_textedit.text(), 200)
        mapping_values["rec_buffer"] = self._wrap(int, self.rec_buf_textedit.text(), 200)
        mapping_values["nr_ecus"] = self._wrap(int, self.nr_ecus_textedit.text(), 0)
        
        if self.ecu_set_te.text():
            self.set_ecu_settings[self._cur_set_entry] = self.ecu_set_te.text()
        mapping_values["ecu_settings"] = self.set_ecu_settings
        
        # Certification and Timing
        self.set_time_lib[self._cur_set_time_entry] = self.ecu_set_time_sel_cb.currentText()  # Final entry
        mapping_values['ecu_timing'] = self.set_time_lib
        mapping_values['has_sec_mod_cert'] = self.has_sec_mod_cert        

#         mapping_values['connected_sec_mod'] = None
        
        return mapping_values

    def preprocess(self, env, mapp):
        
        self.ecu_spec = SimpleECUSpec(mapp["id_list"] , mapp["send_buffer"], mapp["rec_buffer"])        
        for k in mapp["ecu_settings"]:
            self.ecu_spec.set_ecu_setting(k, mapp["ecu_settings"][k])  
                
        self.ecu_group = api.ecu_sim_api.set_ecus(env, mapp["nr_ecus"], 'SecureECU', self.ecu_spec)
    
    def get_actions(self):
        ''' returns the connections that can be made '''        
        
        actions = {}
        
        actions['valid_cert'] = 'Generate Valid Certificate'
                
        return actions
        
    def execute_action(self, env_connect, *args):
        pass

    def main_process(self, env, mapp):
        print("Main")

    def postprocess(self, env, mapp):
        print("Post")

    def _create_widgets(self, parent):

        # Layout
        GBuilder().set_props(self, None, 100, 100)  
        main_lo = QVBoxLayout()
        self.setLayout(main_lo)
        
        # Title
        main_lo.addWidget(GBuilder().label(parent, "<b>Description:</b>"))
        hl = QHBoxLayout()        
        self.desc_label = GBuilder().label(parent, "Add a new SecureECU. This ECU resembles the ECU Part in a Lightweight Authentication Mechanism.")
        self.desc_label.setFixedWidth(400)
        self.icon = GBuilder().image(parent, SecureECUAddWidget.GUI_ICON, 2)        
        hl.addWidget(self.desc_label)
        hl.addWidget(self.icon)
        main_lo.addLayout(hl)
        
        line = GBuilder().hor_line(parent)
        main_lo.addWidget(line);
                
        # Constructor Inputs
        main_lo.addWidget(GBuilder().label(parent, "<b>General Information:</b>"))
        lo0, self.id_list = GBuilder().label_text(parent, "List of IDs (optional):", label_width=120)
        lo1, self.send_buf_textedit = GBuilder().label_text(parent, "Sending BufferSize:", label_width=120)
        lo2, self.rec_buf_textedit = GBuilder().label_text(parent, "Receiving Buffer Size:", label_width=120)
        lo3, self.nr_ecus_textedit = GBuilder().label_text(parent, "Number of ECUs:", label_width=120)
        main_lo.addLayout(lo0)
        main_lo.addLayout(lo1)
        main_lo.addLayout(lo2)
        main_lo.addLayout(lo3)

        # ECU Settings
        items = self._get_ecu_settings()
        hl, self.ecu_set_cb, self.ecu_set_te = GBuilder().combobox_text(parent, items, self._set_cb_changed)
        self._cur_set_entry = self.ecu_set_cb.currentText()
        main_lo.addLayout(hl)
        
        # Timing Mapping 
        line = GBuilder().hor_line(parent)
        main_lo.addWidget(line);
        lab = GBuilder().label(parent, "<b>Timing and Certification:</b>")
        lab.setFixedHeight(20)
        main_lo.addWidget(lab)
        
        itm = StdSecurECUTimingFunctions()
        avail_items = itm.available_tags
        items = itm.function_map.keys()        
        hl1 = QHBoxLayout()
        self.ecu_set_time_cb = GBuilder().combobox(parent, items, self._set_time_cb_changed)
        self._cur_set_time_entry = self.ecu_set_time_cb.currentText()   
        
        self.ecu_set_time_sel_cb = GBuilder().combobox(parent, avail_items, self._set_time_cb_changed)
        self._cur_set_time_sel_entry = self.ecu_set_time_sel_cb.currentText()
        hl1.addWidget(self.ecu_set_time_cb)
        hl1.addWidget(self.ecu_set_time_sel_cb)
        main_lo.addLayout(hl1)

        # Certification (has a valid certificate or not)
#         hl, self.has_sec_mod_cert_cb, lab = GBuilder().label_combobox(parent, "Has Security Module Certificate", ["Yes", "No"], self._has_sec_mod_cb_changed)
#         main_lo.addLayout(hl)

    def _get_ecu_settings(self):
        SecureECU().settings = sorted(SecureECU().settings, key=lambda key: SecureECU().settings[key])
        
        return SecureECU().settings
        
    def _has_sec_mod_cb_changed(self):
        try:
            if self.has_sec_mod_cert_cb.currentText() == "Yes":
                self.has_sec_mod_cert = True
            else:
                self.has_sec_mod_cert = False
        except:
            pass
        
    def _set_time_cb_changed(self):   

        try:
            # Save old value
            if self._cur_set_time_entry == self.ecu_set_time_cb.currentText():
                self.set_time_lib[self._cur_set_time_entry] = self.ecu_set_time_sel_cb.currentText()
                self._cur_set_time_entry = self.ecu_set_time_cb.currentText()
                return
            
            # Load the next one
            try:
                index = self.ecu_set_time_sel_cb.findText(self.set_time_lib[self.ecu_set_time_cb.currentText()])
                self.ecu_set_time_sel_cb.setCurrentIndex(index)                           
            except:
                self.ecu_set_time_sel_cb.setCurrentIndex(0)        
            self._cur_set_time_entry = self.ecu_set_time_cb.currentText()                           
        except:
            pass
        
    def _set_cb_changed(self):        
        try:
            # Save old value
            if self.ecu_set_te.text():
                self.set_ecu_settings[self._cur_set_entry] = self.ecu_set_te.text()
            
            # Load the next one
            try:
                self.ecu_set_te.setText(self.set_ecu_settings[self.ecu_set_cb.currentText()])                
            except:
                self.ecu_set_te.setText('')            
            self._cur_set_entry = self.ecu_set_cb.currentText()
        except:
            pass
        
    def _wrap(self, func, prime, second):
        try:
            el = func(prime)
            return el
        except:
            return second
        
class SecLwAuthSecurityModuleAddWidget(AbstractAddPlugin):
    ''' This is the interface that connects the GUI and the actions to
        execute '''

    GUI_NAME = "Sec. Module"
    GUI_ICON = os.getcwd() + r'/icons/secmod_ecu.png'

    def __init__(self, parent):
        AbstractAddPlugin.__init__(self, parent)        
        self._create_widgets(parent)
        
        self.set_ecu_settings = {}
        self.set_time_lib = {}
        self.has_sec_mod_cert = False
        self.id = uuid.uuid4()
        self.ecu_group = None

    def get_actions(self):
        ''' returns the actions shown in the 
            context menu '''        
        
        actions = {}
        
        actions['reg_ecus'] = 'Register ECU Groups'
        actions['valid_cert'] = 'Generate valid certificates'

        return actions

    def set_gui(self, mapp):
        ''' set the gui from the map received '''
        try:
            if "id_list" in mapp: self.id_list.setText(str(mapp["id_list"]))
            if "send_buffer" in mapp: self.send_buf_textedit.setText(str(mapp["send_buffer"]))
            if "rec_buffer" in mapp: self.rec_buf_textedit.setText(str(mapp["rec_buffer"]))
            if "nr_ecus" in mapp: self.nr_ecus_textedit.setText(str(mapp["nr_ecus"]))
            
            if "ecu_settings" in mapp: self.set_ecu_settings = mapp["ecu_settings"]
            self._set_cb_changed()
            
            if "ecu_timing" in mapp: self.set_time_lib = mapp["ecu_timing"]
            index = self.ecu_set_time_sel_cb.findText(self.set_time_lib[self.ecu_set_time_cb.currentText()])
            self.ecu_set_time_sel_cb.setCurrentIndex(index)  
            self._cur_set_time_entry = self.ecu_set_time_cb.currentText()  
            
            if "has_sec_mod_cert" in mapp: self.has_sec_mod_cert = mapp["has_sec_mod_cert"]
            if not self.has_sec_mod_cert: self.has_sec_mod_cert_cb.setCurrentIndex(0)
            
        except:
            ECULogger().log_traceback()

    def get_map(self):
        
        mapping_values = {}
        
        # Read the values from the gui and save them  
        # General Information      
        mapping_values["id_list"] = self._wrap(eval, self.id_list.text(), [])
        mapping_values["send_buffer"] = self._wrap(int, self.send_buf_textedit.text(), 200)
        mapping_values["rec_buffer"] = self._wrap(int, self.rec_buf_textedit.text(), 200)
        mapping_values["nr_ecus"] = self._wrap(int, self.nr_ecus_textedit.text(), 0)
        
        if self.ecu_set_te.text():
            self.set_ecu_settings[self._cur_set_entry] = self.ecu_set_te.text()
        mapping_values["ecu_settings"] = self.set_ecu_settings
        
        # Certification and Timing
        self.set_time_lib[self._cur_set_time_entry] = self.ecu_set_time_sel_cb.currentText()  # Final entry
        mapping_values['ecu_timing'] = self.set_time_lib
        mapping_values['has_sec_mod_cert'] = self.has_sec_mod_cert
        

        return mapping_values

    def preprocess(self, env, mapp):
        
        self.ecu_spec = SimpleECUSpec(mapp["id_list"] , mapp["send_buffer"], mapp["rec_buffer"])        
        for k in mapp["ecu_settings"]:
            self.ecu_spec.set_ecu_setting(k, mapp["ecu_settings"][k])  
                
        self.ecu_group = api.ecu_sim_api.set_ecus(env, mapp["nr_ecus"], 'SecureECU', self.ecu_spec)

    def main_process(self, env, mapp):
        print("Main")

    def postprocess(self, env, mapp):
        print("Post")
    
    def _create_widgets(self, parent):

        # Layout
        GBuilder().set_props(self, None, 100, 100)  
        main_lo = QVBoxLayout()
        self.setLayout(main_lo)
        
        # Title
        main_lo.addWidget(GBuilder().label(parent, "<b>Description:</b>"))
        hl = QHBoxLayout()        
        self.desc_label = GBuilder().label(parent, "Add a new SecureECU. This ECU resembles the ECU Part in a Lightweight Authentication Mechanism.")
        self.desc_label.setFixedWidth(400)
        self.icon = GBuilder().image(parent, SecLwAuthSecurityModuleAddWidget.GUI_ICON, 2)        
        hl.addWidget(self.desc_label)
        hl.addWidget(self.icon)
        main_lo.addLayout(hl)
        
        line = GBuilder().hor_line(parent)
        main_lo.addWidget(line);
                
        # Constructor Inputs
        main_lo.addWidget(GBuilder().label(parent, "<b>General Information:</b>"))
        lo0, self.id_list = GBuilder().label_text(parent, "List of IDs (optional):", label_width=120)
        lo1, self.send_buf_textedit = GBuilder().label_text(parent, "Sending BufferSize:", label_width=120)
        lo2, self.rec_buf_textedit = GBuilder().label_text(parent, "Receiving Buffer Size:", label_width=120)
        lo3, self.nr_ecus_textedit = GBuilder().label_text(parent, "Number of ECUs:", label_width=120)
        main_lo.addLayout(lo0)
        main_lo.addLayout(lo1)
        main_lo.addLayout(lo2)
        main_lo.addLayout(lo3)

        # ECU Settings
        items = self._get_ecu_settings()
        hl, self.ecu_set_cb, self.ecu_set_te = GBuilder().combobox_text(parent, items, self._set_cb_changed)
        self._cur_set_entry = self.ecu_set_cb.currentText()
        main_lo.addLayout(hl)
        
        # Timing Mapping 
        line = GBuilder().hor_line(parent)
        main_lo.addWidget(line)
        lab = GBuilder().label(parent, "<b>Timing and Certification:</b>")
        lab.setFixedHeight(20)
        main_lo.addWidget(lab)
        
        itm = StdSecurLwSecModTimingFunctions()
        avail_items = itm.available_tags
        items = itm.function_map.keys()        
        hl1 = QHBoxLayout()
        self.ecu_set_time_cb = GBuilder().combobox(parent, items, self._set_time_cb_changed)
        self._cur_set_time_entry = self.ecu_set_time_cb.currentText()   
        
        self.ecu_set_time_sel_cb = GBuilder().combobox(parent, avail_items, self._set_time_cb_changed)
        self._cur_set_time_sel_entry = self.ecu_set_time_sel_cb.currentText()
        hl1.addWidget(self.ecu_set_time_cb)
        hl1.addWidget(self.ecu_set_time_sel_cb)
        main_lo.addLayout(hl1)

        # Certification (has a valid certificate or not)
#         hl, self.has_sec_mod_cert_cb, lab = GBuilder().label_combobox(parent, "Has Security Module Certificate", ["Yes", "No"], self._has_sec_mod_cb_changed)
#         main_lo.addLayout(hl)
        
    def _get_ecu_settings(self):
        sett = SecLwAuthSecurityModule()
        sett.settings = sorted(sett.settings, key=lambda key: sett.settings[key])
        
        return sett.settings
        
    def _has_sec_mod_cb_changed(self):
        try:
            if self.has_sec_mod_cert_cb.currentText() == "Yes":
                self.has_sec_mod_cert = True
            else:
                self.has_sec_mod_cert = False
        except:
            pass
        
    def _set_time_cb_changed(self):   

        try:
            # Save old value
            if self._cur_set_time_entry == self.ecu_set_time_cb.currentText():
                self.set_time_lib[self._cur_set_time_entry] = self.ecu_set_time_sel_cb.currentText()
                self._cur_set_time_entry = self.ecu_set_time_cb.currentText()
                return
            
            # Load the next one
            try:
                index = self.ecu_set_time_sel_cb.findText(self.set_time_lib[self.ecu_set_time_cb.currentText()])
                self.ecu_set_time_sel_cb.setCurrentIndex(index)                           
            except:
                self.ecu_set_time_sel_cb.setCurrentIndex(0)        
            self._cur_set_time_entry = self.ecu_set_time_cb.currentText()                           
        except:
            pass
        
    def _set_cb_changed(self):        
        try:
            # Save old value
            if self.ecu_set_te.text():
                self.set_ecu_settings[self._cur_set_entry] = self.ecu_set_te.text()
            
            # Load the next one
            try:
                self.ecu_set_te.setText(self.set_ecu_settings[self.ecu_set_cb.currentText()])                
            except:
                self.ecu_set_te.setText('')            
            self._cur_set_entry = self.ecu_set_cb.currentText()
        except:
            pass
        
    def _wrap(self, func, prime, second):
        try:
            el = func(prime)
            return el
        except:
            return second
          
class StdBusAddWidget(AbstractAddPlugin):
    ''' This is the interface that connects the GUI and the actions to
        execute '''

    GUI_NAME = "CAN BUS"
    GUI_ICON = os.getcwd() + r'/icons/can.png'

    def __init__(self, parent):
        AbstractAddPlugin.__init__(self, parent)        
        self._create_widgets(parent)        
        self.parent = parent
                
        self.id = uuid.uuid4()        
        self.bus_group = None
        
    def set_gui(self, mapp):
        ''' set the gui from the map received '''
        try:
            if "id_list" in mapp: self.id_list.setText(str(mapp["id_list"]))
            if "nr_busses" in mapp: self.nr_ecus_textedit.setText(str(mapp["nr_busses"]))
            
        except:
            ECULogger().log_traceback()

    def get_map(self):
                
        mapping_values = {}
        # Read the values from the gui and save them  
        # General Information      
        mapping_values["id_list"] = self._wrap(eval, self.id_list.text(), [])
        mapping_values["nr_busses"] = self._wrap(int, self.nr_ecus_textedit.text(), 0)
                
        return mapping_values

    def preprocess(self, env, mapp):
        pass
    
    def get_actions(self):
        ''' returns the connections that can be made '''        
        
        actions = {}
        
        actions['connect_group'] = 'Connect ECU Group'

        return actions
        
    def execute_action(self, env_connect, *args):
        pass
                
    def main_process(self, env, mapp):
        print("Main")

    def postprocess(self, env, mapp):
        print("Post")
        
    def _create_widgets(self, parent):

        # Layout
        GBuilder().set_props(self, None, 100, 100)  
        main_lo = QVBoxLayout()
        self.setLayout(main_lo)
        
        # Title
        main_lo.addWidget(GBuilder().label(parent, "<b>Description:</b>"))
        hl = QHBoxLayout()        
        self.desc_label = GBuilder().label(parent, "Add a new Standard Bus. This CAN Bus is a simple implementation of a automotive link.")
        self.desc_label.setFixedWidth(400)
        self.icon = GBuilder().image(parent, StdBusAddWidget.GUI_ICON, 2)        
        hl.addWidget(self.desc_label)
        hl.addWidget(self.icon)
        main_lo.addLayout(hl)
        
        line = GBuilder().hor_line(parent)
        main_lo.addWidget(line);
                
        # Constructor Inputs
        main_lo.addWidget(GBuilder().label(parent, "<b>General Information:</b>"))       
        lo0, self.id_list = GBuilder().label_text(parent, "List of IDs (optional):", label_width=120)
        lo1, self.nr_ecus_textedit = GBuilder().label_text(parent, "Number of Busses:", label_width=120)
        main_lo.addLayout(lo0)
        main_lo.addLayout(lo1)
                
        
    def _wrap(self, func, prime, second):
        try:
            el = func(prime)
            return el
        except:
            return second
