import uuid

class AutomotiveComponent(object):
    ''' component of the Automotive Environment holding
        common properties'''
    
    def __init__(self, sim_env, comp_id=uuid.uuid4()):
        ''' Constructor
            
            Input:    sim_env        simpy.Environment        environment of this component
                      comp_id         string                  identifier for this component
        '''
        self.sim_env = sim_env
        self.comp_id = comp_id
        self.time = {}
        
    
    def set_timing(self, timing_dict):
        ''' sets the timing parameters in this 
        specific class 
        
        Input:    timing_dict  dictionary    
        '''
        
        
