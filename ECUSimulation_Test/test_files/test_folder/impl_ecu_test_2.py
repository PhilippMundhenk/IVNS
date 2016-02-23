from components.base.ecu.types.abst_ecu import AbstractECU
from components.base.ecu.hardware.ecu_hardware import ECUHardware
from components.base.ecu.hardware.impl_transceiver_std import StdTransceiver
from components.base.ecu.hardware.impl_controller_can_std import StdCanController
from components.base.ecu.software.impl_app_layer_simple import SimpleApplicationLayer
from components.base.ecu.software.impl_comm_module_simple import StdCommModule
from components.base.ecu.software.ecu_software import ECUSoftware
from components.base.ecu.hardware.impl_micro_controller_std import StdMicrocontroller
from tools.ecu_logging import try_ex

class TestECU2(AbstractECU):

    def __init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer):
        ''' Expects a SimpleAppLayer or a subclass of it in the ECUSoftware'''
                
        # Set Settings
        self.set_settings()
        if sim_env == None: return  # No instantiation    
        AbstractECU.__init__(self, sim_env, ecu_id, data_rate)
                
        self.ecuHW = ECUHardware(sim_env, StdTransceiver(sim_env), StdCanController(sim_env, size_receive_buffer, size_sending_buffer), StdMicrocontroller(sim_env))
        self.ecuSW = ECUSoftware(sim_env, StdCommModule(sim_env), SimpleApplicationLayer(sim_env, ecu_id))
        
        self._connect_hw_sw()          

    @try_ex
    def get_type_id(self):
        return "SimpleECU"
    
    @try_ex
    def set_settings(self):
        
        self.settings = {}
        
        # Parameter for Authenticator
        self.settings['t_commod_receive_process'] = 'ecuSW.comm_mod.STDCM_RECEIVE_PROCESS'
        self.settings['t_commod_send_process'] = 'ecuSW.comm_mod.STDCM_SEND_PROCESS'
        
