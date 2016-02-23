import simpy
from components.base.ecu.software.abst_application_layer import AbstractApplicationLayer
from tools.ecu_logging import ECULogger as L

class SimpleApplicationLayer(AbstractApplicationLayer):
    ''' This class implements an Application 
        running on a specific ECU'''
    
    def __init__(self, sim_env, ecu_id=-1):
        ''' Constructor
            
            Input:    sim_env    simpy.Environment        environment of this component
                      ecu_id     string                   id of the corresponding AbstractECU
            Output:   -
        '''
        AbstractApplicationLayer.__init__(self, sim_env, ecu_id)
        
        self.sync = simpy.Store(self.sim_env, capacity=1)     

    
    def _main_receive(self):
        ''' supposed to do nothing'''
        while True:                
            ''' 1. receive Stuff via the connected transmission module, stuck until message received '''
            [self.msg_id, self.msg_data] = yield self.sim_env.process(self.comm_mod.receive_msg())
            if self.msg_id: 
                L().log(400, self.sim_env.now, self._ecu_id, [self.msg_id, self.msg_data])
                   
             
    def _main_send(self): 
        ''' supposed to do nothing'''
        while True:
            yield self.sim_env.timeout(10)
        
    
    def main(self):
        ''' 
        '''
        self.sim_env.process(self._main_receive())
        self.sim_env.process(self._main_send())
        yield self.sim_env.timeout(0)


        
    
