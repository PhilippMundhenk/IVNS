from components.base.ecu.software.ecu_software import ECUSoftware
from components.base.ecu.types.impl_ecu_simple import SimpleECU
from tools.ecu_logging import ECULogger as L
from components.security.ecu.software.impl_comm_module_tesla import TeslaCommModule
from components.security.ecu.software.impl_app_layer_tesla import TeslaApplicationLayer
from enums.sec_cfg_enum import EnumTrafor, SymAuthMechEnum, AuKeyLengthEnum, \
    AsymAuthMechEnum
from config.timing_db_admin import TimingDBMap
from tools.general import General as G
import logging
import math
from math import ceil
from config import can_registration
from components.security.ecu.types.impl_ecu_tesla import TeslaECU
from testcases.devices.ecus.impl_app_layer_test_tesla import TeslaTestApplicationLayer


class TestTeslaECU(TeslaECU):
    '''
    this ECU enables secure communication using the TESLA protocol 
    on the communication layer
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
        # Set Settings
        self.set_settings()
        self._authenticated = False
        self._allowed_streams = can_registration.TESLA_MESSAGES
        
        # no instantiation
        if sim_env == None: return 
        
        # set SW and HW
        SimpleECU.__init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer)                
        self.ecuSW = ECUSoftware(sim_env, TeslaCommModule(sim_env, ecu_id), \
                                  TeslaTestApplicationLayer(sim_env, ecu_id))
        
        # connect 
        self._connect_hw_sw()                
   
    def get_type_id(self):
        ''' returns the id of this ECU type
        
            Input:    -
            Output:   ecu_type    string    type of this ECU; e.g.'TLSECU'
        '''
        return "TestTeslaECU"
    


