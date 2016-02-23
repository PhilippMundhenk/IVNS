from components.base.ecu.software.abst_comm_layers import AbstractPhysicalLayer

class StdPhysicalLayer(AbstractPhysicalLayer):
    ''' This class implements the Physical Layer of
        the implementation of a secure Communication 
        Module, does actually nothing'''
    
    def __init__(self, sim_env):
        ''' Constructor
            
            Input:    sim_env              simpy.Environment                environment of this component
            Output:   -
        '''
        AbstractPhysicalLayer.__init__(self, sim_env)
        
    
    def bus_free(self):
        ''' true if the connected Bus is free 
        
            Input:     -
            Output:    bool    boolean    true if the connected bus is free
        '''
        if self.transceiver.bus_free():
            return True
        return False
    
    
    def put(self, message):
        ''' puts the message on the bus via the transceiver, False if it was  
            overridden by another message with higher priority
            
            Input:     message    Object    message to be pushed on the bus
            Output:    -
        '''
        # try to put message
        success = yield self.sim_env.process(self.transceiver.put(message))
        
        return success

    
    def wake_if_channel_free(self):
        ''' stuck until bus is free again 
        
            Input:     -
            Output:     -
        '''
        yield self.sim_env.process(self.transceiver.connected_bus.wait_until_free())

