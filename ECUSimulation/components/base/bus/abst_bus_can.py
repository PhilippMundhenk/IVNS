from components.base.automotive_component import AutomotiveComponent

class AbstractCANBus(AutomotiveComponent):
    '''
    This abstract class resembles the interface of a Bus
    '''

    def __init__(self, sim_env, bus_id, data_rate, avg_ecu_dist=2):
        ''' Constructor
            
            Input:    sim_env        simpy.Environment         environment in which this Bus acts
                      bus_id         string                    id of this Bus object
                      data_rate      float                     datarate of this bus
                      avg_ecu_dist   float                     average distance between two connected ECUs
                
            Output:   -                  
        '''
        AutomotiveComponent.__init__(self, sim_env, bus_id) 

        self.current_bus = None
        self.data_rate = data_rate  # data rate of the bus
        self.avg_dist_between_ecus = avg_ecu_dist  # meter        
        self.effective_datarate = float("inf")  # Bit per second
        self.effective_bittime = 1 / self.effective_datarate  # determined by the ecu/self with slowest rate 

        self.connected_ecus = []
        self.connected_gws = []
           
                
    def connect_ecu(self, new_ecu):
        ''' connects an ECU to the bus 
        
            Input:     new_ecu       AbstractECU    ECU to be connected
            Output:     -            
        '''
        if new_ecu not in self.connected_ecus:
            self.connected_ecus.append(new_ecu)
           
     
    def connect_gateway(self, new_gateway):
        ''' connects a gateway to the bus 
        
            Input:     new_gateway       Gateway    Gateway to be connected
            Output:     -  
        '''
        if new_gateway not in self.connected_gws:
            self.connected_gws.append(new_gateway)
           
     
    def put_message(self, message):
        ''' puts messages on the bus
            
            Input:     message    object        message to be put on the bus
            Output:    -
        '''
        pass
           
     
    def process(self):
        ''' runs in parallel to all other processes. This method
            is meant to transmit messages that it gets from one Ecu to all of 
            the connected ECUs
        
            Input:      -
            Outputt:    -
        '''
        while True:
            yield self.sim_env.timeout(1); 
           
     
    def _GET_ABSTRACT_BUS(self):
        ''' indicates that this class and its' subclasses are buses'''
        return True
    
