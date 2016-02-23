from components.base.automotive_component import AutomotiveComponent

class AbstractController(AutomotiveComponent):
    ''' 
    This abstract class defines the interface of
    a controller being one HW Component of an ECU
    '''
    
    def __init__(self, sim_env):
        ''' Constructor
            
            Input:    sim_env    simpy.Environment        environment of this component
            Output:   -
        '''
        AutomotiveComponent.__init__(self, sim_env)
        self.connected_transceiver = None
        self.connnected_mic_con = None
        
        