from components.base.ecu.hardware.abst_micro_controller import AbstractMicrocontroller

class StdMicrocontroller(AbstractMicrocontroller):
    ''' 
    This Class implements the Microcontroller used 
    for secure Authentication 
    '''
    
    def __init__(self, sim_env):
        ''' Constructor
            
            Input:    sim_env                    simpy.Environment         environment of this component                      
            Output:   -
        '''
        AbstractMicrocontroller.__init__(self, sim_env)


        