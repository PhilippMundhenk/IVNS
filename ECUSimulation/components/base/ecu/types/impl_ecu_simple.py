from components.base.ecu.types.abst_ecu import AbstractECU
from components.base.ecu.hardware.ecu_hardware import ECUHardware
from components.base.ecu.hardware.impl_transceiver_std import StdTransceiver
from components.base.ecu.hardware.impl_controller_can_std import StdCanController
from components.base.ecu.software.impl_app_layer_simple import SimpleApplicationLayer
from components.base.ecu.software.impl_comm_module_simple import StdCommModule
from components.base.ecu.software.ecu_software import ECUSoftware
from components.base.ecu.hardware.impl_micro_controller_std import StdMicrocontroller

class SimpleECU(AbstractECU):

    def __init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer):
        ''' Constructor
            
            Input:  sim_env                simpy.Environment         environment in which this Bus acts
                    bus_id                 string                    id of this Bus object
                    data_rate              float                     datarate of this bus
                    avg_ecu_dist           float                     average distance between two connected ECUs
                    size_sending_buffer    float                     size of the sending buffer of this ECU
                    size_receive_buffer    float                     size of the receiving buffer of this ECU                              
            Output:   -                  
        '''
                        
        # set settings
        self.set_settings()
        if sim_env == None: return  # no instantiation    
        AbstractECU.__init__(self, sim_env, ecu_id, data_rate)
                
        # initialize 
        self.ecuHW = ECUHardware(sim_env, StdTransceiver(sim_env), StdCanController(sim_env, size_receive_buffer, size_sending_buffer), StdMicrocontroller(sim_env))
        self.ecuSW = ECUSoftware(sim_env, StdCommModule(sim_env), SimpleApplicationLayer(sim_env, ecu_id))
        
        # connect layers
        self._connect_hw_sw()          

    
    def get_type_id(self):
        ''' returns the id of this ECU type
        
            Input:    -
            Output:   ecu_type    string    type of this ECU; e.g.'TLSECU'
        '''
        return "SimpleECU"
    
    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        # Parameter for Authenticator
        self.settings['t_commod_receive_process'] = 'ecuSW.comm_mod.STDCM_RECEIVE_PROCESS'
        self.settings['t_commod_send_process'] = 'ecuSW.comm_mod.STDCM_SEND_PROCESS'
        
    @property    
    def ecu_id(self):
        return self._ecu_id
    
    @ecu_id.setter    
    def ecu_id(self, value):
        self._ecu_id = value   
        try:
            self.ecuSW.comm_mod.ecu_id = value
        except:
            pass