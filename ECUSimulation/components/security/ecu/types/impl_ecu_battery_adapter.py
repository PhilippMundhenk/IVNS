from components.base.ecu.software.ecu_software import ECUSoftware
from components.security.ecu.software.impl_comm_module_secure import SecureCommModule
from components.security.ecu.software.impl_app_layer_bat_man import BatManApplicationLayer
from components.security.ecu.types.impl_ecu_secure import SecureECU

class BatManAdapterECU(SecureECU):
    '''
    this ECU is used to wrap the battery management CMUs into a ECU. Thereby it
    is able to create any constellation desired
    '''
    def __init__(self, sim_env=None, ecu_id=None, data_rate=None, size_sending_buffer=None, size_receive_buffer=None):
        ''' Constructor
        
            Input:  sim_env                simpy.Environment        environment in which this ECU lives
                    ecu_id                 string                   id of this ECU component 
                    data_rate              integer                  data_rate of the connected bus
                    size_sending_buffer    float                    size of the sending buffer of this ECU
                    size_receive_buffer    float                    size of the receiving buffer of this ECU   
        
        '''
        # set settings
        self.set_settings()
        
        # no instantiation
        self._authenticated = False
        if sim_env == None: return
        
        # create software
        SecureECU.__init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer)                
        self.ecuSW = ECUSoftware(sim_env, SecureCommModule(sim_env, ecu_id), BatManApplicationLayer(sim_env, ecu_id))
        
        # connect 
        self._connect_hw_sw()                
        
    def connect_adapter(self, adapter):
        ''' this method connects a BatManCANBusAdapter to this 
            ECU thus enabling to communicate with the 
            connecte CMU that instantiates this adapter
            
            Input:     adapter        BatManCANBusAdapter    adapter connected to the CMU in the battery management environment
            Output:    -        
        '''
        self.ecuSW.app_lay.set_bat_man_adapter(adapter)