from components.base.ecu.software.ecu_software import ECUSoftware
from components.security.ecu.software.impl_comm_module_secure import SecureCommModule
from components.security.ecu.software.impl_app_layer_regular import RegularApplicationLayer

from components.security.ecu.types.impl_ecu_secure import SecureECU

class RegularSecureECU(SecureECU):
    '''
    this class ressembles an ECU that can send messages in defined sending intervals starting from a certain point in 
    time. The message size and input can be defined as well. 
    '''
    
    def __init__(self, sim_env=None, ecu_id=None, data_rate=None, size_sending_buffer=None, size_receive_buffer=None):        
        ''' Constructor
        
            Input:  sim_env                simpy.Environment        environment in which this ECU lives
                    ecu_id                 string                   id of this ECU component 
                    data_rate              integer                  data_rate of the connected bus
                    size_sending_buffer    float                    size of the sending buffer of this ECU
                    size_receive_buffer    float                    size of the receiving buffer of this ECU   
            Output: -
        '''
        
        # set settings
        self.set_settings()
        
        # no instantiation
        if sim_env == None: return  
        
        # set SW and HW
        SecureECU.__init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer)   
        
        # create software
        self.ecuSW = ECUSoftware(sim_env, SecureCommModule(sim_env, ecu_id), RegularApplicationLayer(sim_env, ecu_id))
        
        # connect
        self._connect_hw_sw()
        
    
    def add_sending(self, start_time, interval, message_id, data, data_len):
        ''' this method adds a new sending action to the application layer of this 
            ECU. Then the message will start sending messages in the defined interval
            starting at the specified start_time
            
            Input:  start_time    float            time at which the first message is sent
                    interval      float            period within which the messages are sent
                    message_id    integer          message identifier of the messages that are sent
                    data          object/..        content of the messages that are sent
                    data_length   float            size of one message
            Output: -        
        '''
        self.ecuSW.app_lay.add_sending(start_time, interval, message_id, data, data_len)