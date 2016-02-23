from components.base.ecu.hardware.abst_transceiver import AbstractTranceiver
import config.timing_registration as time
from tools.general import General as G

class StdTransceiver(AbstractTranceiver):
    ''' 
    This class implements the interface of
    a Transceiver being one HW Component of an ECU
    '''
    
    def __init__(self, sim_env):
        ''' Constructor
            
            Input:    sim_env                    simpy.Environment         environment of this component                      
            Output:   -
        '''
        AbstractTranceiver.__init__(self, sim_env)        
    
        # initialize parameters        
        self.filter_active = False
        self.allowed_items = []
        self.set_settings()
        
        # project parameter
        self.ST_PUT_ON_BUS = time.ST_PUT_ON_BUS

    
    def bus_free(self):
        ''' True if the bus is free
            
            Input:   -
            Output:  bool    boolean    True if the connected bus is free        
        '''
        if self.connected_bus.current_message == None:
            return True
        return  False
    
    
    def get(self, message):
        ''' this method is called once the bus
            is putting something to the receiver
        
        
            Input:    message    object        message that was received by this transceiver
            Output:   -           
        '''
        
        # if the ecu is inactive discard this message
        if not self.ecu_is_active: 
            return 
        
        # filter if active
        if self.filter_active:
            if not message.message_identifier in self.allowed_items: return            
        
        # receive buffer overflow
        size_after_new, size_now = self._extract_sizes(message)                
        if size_after_new > size_now: return G().val_log_info(None, 800)
        
        # put to receive buffer
        self.connected_controller.receive_buffer.put(message)
        
    
    
    def install_filter(self, message_id_list):
        ''' only message ids that are in this list are allowed 
            others are discarded
        
            Input:    message_id_list    list    list of message ids that are allowed by this transceiver
            Output:    -
        '''
        self.allowed_items = message_id_list
        self.filter_active = True
    
        
    def put(self, msg):
        ''' this method puts a message to the connected
            bus
        
            Input:     -
            Output:    ok        boolean    true if putting was successful
        '''
        if self.ST_PUT_ON_BUS != 0:
            G().to_t(self.sim_env, self.ST_PUT_ON_BUS * self._jitter, 'ST_PUT_ON_BUS', self.__class__.__name__, self)
            yield self.sim_env.timeout(self.ST_PUT_ON_BUS * self._jitter)
        
        ok = yield self.sim_env.process(self.connected_bus.put_message(msg))
        return ok
    
    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        self.settings['t_put_on_bus'] = 'ST_PUT_ON_BUS'
        
    def _extract_sizes(self, message):
        ''' returns the sizes of the buffer after an addition
            and before the addition of the new message
        
            Output:    size_after_new    float    size of buffer after addition in byte
                       size_now          float    size of buffer before addition in byte
        '''
        size_after_new = self.connected_controller.receive_buffer.get_bytes() + (float(message.msg_length_in_bit) / 8.0)
        size_now = self.connected_controller.receive_buffer.max_size
        return size_after_new, size_now
