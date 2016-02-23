from components.base.automotive_component import AutomotiveComponent

class AbstractTranceiver(AutomotiveComponent):
    ''' 
    This abstract class defines the interface of
    a Transceiver being one HW Component of an ECU
    '''

    
    def __init__(self, sim_env):
        ''' Constructor
            
            Input:    sim_env    simpy.Environment        environment of this component
            Output:   -
        '''
        AutomotiveComponent.__init__(self, sim_env)
        self.connected_bus = None
        self.connected_controller = None
        self._jitter = 1
        self.ecu_is_active = True
           
     
    def connect_bus(self, bus):
        ''' Connects this transceiver to a bus
        
            Input:   bus    CANBus    bus that will be connected
            Output:  -
        '''
        self.connected_bus = bus
        
    
    def get(self, message):
        ''' this method is called once the bus
            is putting something to the receiver
        
        
            Input:    message    object        message that was received by this transceiver
            Output:   -           
        '''
        
    
    def put(self):
        ''' this method puts a message to the connected
            bus
        
            Input:     -
            Output:    boolean    boolean    true if putting was successful
        '''
        
    
    def bus_free(self):
        ''' True if the bus is free
            
            Input:   -
            Output:  bool    boolean    True if the connected bus is free        
        '''
        return None