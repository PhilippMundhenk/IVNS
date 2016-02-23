from components.base.automotive_component import AutomotiveComponent
from config import project_registration as proj
from tools.ecu_logging import ECULogger as L
import random


class AbstractECU(AutomotiveComponent):
    ''' 
    This abstract class defines the interface of
    an ECU as it is found in an automotive network
    '''
    
    def __init__(self, sim_env, ecu_id, data_rate):
        ''' Constructor
            
            Input:    sim_env    simpy.Environment        environment of this component
                      ecu_id     string                   id of the corresponding AbstractECU
                      data_rate  float                    datarate of the ecu
            Output:   -
        '''
        AutomotiveComponent.__init__(self, sim_env)
        
        self._ABSTRACT_ECU = True
        
        self._ecu_id = ecu_id  # ID of the ECU
        self.ecuSW = None  # what is done
        self.ecuHW = None  # what is used to make it happen
        self.MessageClass = proj.BUS_MSG_CLASS  # what kind of messages are exchanged        
        self.connected_bus = None  # Bus that is connected to the ECU
        self.data_rate = proj.BUS_ECU_DATARATE  # Datarate with which bits are put on the bus
        
        self._effective_datarate = 0  # Bit per second
        self._effective_bittime = 0  # seconds
        self._jitter = 1
        self.startup_delay = False
    
    def set_startup_delay(self, start_time):
        ''' this method sets the startup delay. When this delay is set
            this ECU is activated after the defined start time
        
            Input:    start_time    float        time when the ECU starts running
            
            Output:    -
        '''
        self.startup_delay = start_time      
        if start_time:  
            self.ecuHW.transceiver.ecu_is_active = False
        
    def set_jitter(self, jitter_range):
        ''' sets the jitter which will be multiplied onto each 
            timeout value. It will be within jitter_range
            e.g. jitter_range of 0.1 means that any random value
                 between 1.0 and 1.1 will be used 
            
            Input:     jitter_range:    float    dispersion from 1.0
            Output:    -        
        '''
        # determine jitter
        self._jitter = 1 + (random.random() * jitter_range)
            
        # apply jitter on layers
        try: self.ecuSW.comm_mod.physical_lay.transceiver._jitter = self._jitter
        except: pass   
        
        try: self.ecuSW.comm_mod._jitter = self._jitter
        except: pass 
            
        try: self.ecuSW.comm_mod.transp_lay._jitter = self._jitter
        except: pass 
            
        try: self.ecuSW.comm_mod.datalink_lay._jitter = self._jitter
        except: pass 
        
        try: self.ecuSW.comm_mod.physical_lay.transceiver._jitter = self._jitter
        except: pass   
         
        try: self.ecuSW.app_lay._jitter = self._jitter
        except: pass      
            
           
    def _connect_hw_sw(self):
        ''' connect all hardware components with their
            associated software connections
        
            Input:     -
            Output:    -
        '''        
        
        # application Layer
        self.ecuSW.app_lay.microcontroller = self.ecuHW.mic_controller    
        
        # physical and data link layer '''
        self.ecuSW.comm_mod.datalink_lay.controller = self.ecuHW.controller
        self.ecuSW.comm_mod.physical_lay.transceiver = self.ecuHW.transceiver                      
        self.ecuSW.comm_mod.datalink_lay.effective_bittime = self._effective_bittime      
    
    
    def connect_to(self, bus):
        ''' connects the bus to the ECU 
        
            Input:    bus     CANBus     Bus that will be connected
            Output:   -
        '''
        self.ecuHW.transceiver.connect_bus(bus)
        self.connected_bus = bus
        
    
    def get_type_id(self):
        ''' returns the id of this ECU type
        
            Input:    -
            Output:   ecu_type    string    type of this ECU; e.g.'TLSECU'
        '''
        raise NotImplementedError(" get_type_id() was not implemented by class %s" % self.__class__)
                          
    
    def get_rec_buffer_items(self):
        ''' returns the current content of the receiving buffer 
            
            Input:      -
            Output:     rec_buffer    list    list of items in the receiving buffer
        '''
        return self.ecuHW.controller.receive_buffer.items
    
    
    def get_trans_buffer_items(self):
        ''' returns the current content of the transmit buffer 
            
            Input:      -
            Output:     trans_buffer    list    list of items in the transmit buffer
        '''
        return self.ecuHW.controller.transmit_buffer.items
    
    
    def install_hw_filter(self, allowed_items_list):
        ''' installs a hardware filter that filters all 
            message ids that are not defined in the passed
            list. This filter is applied on the transceiver 
    
            Input:     allowed_items_list    list    list of message_ids that are let pass by the transceiver
            Output:    -
        
        '''
        try:
            self.ecuHW.transceiver.install_filter(allowed_items_list)
        except:
            L().log_err(300)
    
    
    def _GET_ABSTRACT_ECU(self):
        ''' marker that this is a AbstractECU '''
        return self._ABSTRACT_ECU
    
    @property    
    def ecu_id(self):        
        return self._ecu_id
    
    @ecu_id.setter    
    def ecu_id(self, value):        
        self._ecu_id = value
        
    
    def set_monitor(self, monitor):
        self.monitor = monitor
