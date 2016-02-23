from components.base.ecu.types.impl_ecu_simple import SimpleECU
from components.base.ecu.software.ecu_software import ECUSoftware
from components.base.ecu.software.impl_comm_module_segment import SegmentCommModule
from components.base.ecu.software.impl_app_layer_simple import SimpleApplicationLayer


class SegmentingECU(SimpleECU):
    
    
    def __init__(self, sim_env, ecu_id, data_rate, MessageClass, size_sending_buffer, size_receive_buffer):
        ''' Constructor
            
            Input:    sim_env                simpy.Environment        environment of this component
                      ecu_id                 string                   id of the corresponding AbstractECU
                      data_rate              float                    datarate of the ecu
                      MessageClass           class                    class that is used for message transmission
                      size_sending_buffer    integer                  capacity of the sending buffer
                      size_receive_buffer    integer                  capacity of the receiving buffer
            Output:   -
        '''
        SimpleECU.__init__(self, sim_env, ecu_id, data_rate, MessageClass, size_sending_buffer, size_receive_buffer)
        
        # initialize Software
        self.ecuSW = ECUSoftware(sim_env, SegmentCommModule(sim_env, MessageClass), SimpleApplicationLayer(sim_env, ecu_id))
        self.set_settings()
        
        # connect layers
        self._connect_hw_sw()          

    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        # Parameter for Authenticator
        self.settings['t_commod_receive_process'] = 'ecuSW.comm_mod.SCM_RECEIVE_PROCESS'
        self.settings['t_commod_send_process'] = 'ecuSW.comm_mod.SCM_SEND_PROCESS'
        
        
