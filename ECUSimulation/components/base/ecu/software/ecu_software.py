from components.base.automotive_component import AutomotiveComponent

class ECUSoftware(AutomotiveComponent):
    ''' 
    This class defines the Software that is
    running on the ECU Hardware. It consists 
    of an Application running on the application layer 
    and a transmission module handling all lower layers
    '''

    def __init__(self, sim_env, comm_mod, app_lay):
        ''' Constructor
            
            Input:    sim_env          simpy.Environment                environment of this component                      
            Output:   -
        '''
        AutomotiveComponent.__init__(self, sim_env)
        
        self.comm_mod = comm_mod
        self.app_lay = app_lay
        self._connect_layers()
        
    
    def _connect_layers(self):
        ''' Connects the application layer to the communication
            module to be accessible by the communication module
            
            Input:    -    
            Output:   -
        '''
        self.app_lay.comm_mod = self.comm_mod
        
        
        
        