import simpy
from tools.ecu_logging import ECULogger as L
from components.security.ecu.software.impl_app_layer_regular import RegularApplicationLayer
import logging

class SecureApplicationLayer(RegularApplicationLayer):
    ''' This class implements a simple application 
        running on a specific ECU. It is a subclass of
        RegularApplicationLayer. So it is able to send defined
        sending actions
    '''
    
    def __init__(self, sim_env, ecu_id=-1):
        ''' Constructor
            
            Input:  sim_env        simpy.Environment        environment of this component
                    ecu_id         string                   id of the corresponding AbstractECU
            Output: -
        '''
        RegularApplicationLayer.__init__(self, sim_env, ecu_id)        
        self.sync = simpy.Store(self.sim_env, capacity=1)     
        
        

    
    def _main_receive(self):
        ''' infinitely waits for an incoming message and logs it once it arrives
            
            Input:    -
            Output:   -
        '''
        
        while True:
            
            # receive
            result = yield self.sim_env.process(self.comm_mod.receive_msg())
            [self.msg_id, self.msg_data] = [result[0], result[1]]
            
            # log received 1
            # logging.info(" ------------------- %s: ECU %s: received: %s" % \
            #             (self.sim_env.now, self._ecu_id, str([self.msg_id, self.msg_data])))
            
            # log received 2
#             if self.msg_id: L().log(500, self.sim_env.now, self._ecu_id, [self.msg_id, self.msg_data])                           
           
           
            
    
