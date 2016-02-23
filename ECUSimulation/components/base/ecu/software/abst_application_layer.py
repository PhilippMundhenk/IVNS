from components.base.automotive_component import AutomotiveComponent

class AbstractApplicationLayer(AutomotiveComponent):
    ''' 
    This abstract class defines the interface of
    an Application that is running on the ECU
    '''

    def __init__(self, sim_env, ecu_id=-1):
        ''' Constructor
            
            Input:    sim_env    simpy.Environment        environment of this component
                      ecu_id     string                   id of the corresponding AbstractECU
            Output:   -
        '''
        AutomotiveComponent.__init__(self, sim_env)
        
        self._comm_mod = None
        self._jitter = 1
        self._ecu_id = ecu_id
        
        self.microcontroller = None
        self.initial_sending_acts = []
        
    
    def main(self):
        ''' This method is the main entrance point of
        the application running on this specific ECU 
        
        it will be started from the main Method
        
        Input:     -
        Output:    -
        '''
        
    @property    
    def ecu_id(self):
        return self._ecu_id
    
    @ecu_id.setter
    def ecu_id(self, value):
        self._ecu_id = value
        
    @property
    def comm_mod(self):
        return self._comm_mod
    
    @ comm_mod.setter
    def comm_mod(self, value):
        self._comm_mod = value
        
    
