import simpy
from tools.ecu_logging import ECULogger as L
from components.security.ecu.software.impl_app_layer_regular import RegularApplicationLayer
import logging
import random
from testcases.utilities.archSaver import SaveRandom as SR

class TeslaTestApplicationLayer(RegularApplicationLayer):
    ''' This class implements the application layer that
        is used for the Tesla implementation together with
        the test.py module. It simply does three steps. First 
        it waits for the timing synchronization to finish. Then
        it waits unitil the key is exchange before it lastly sends
        a defined number of messages (streams).
    '''
    
    def __init__(self, sim_env, ecu_id=-1):
        ''' Constructor
            
            Input:  sim_env        simpy.Environment        environment of this component
                    ecu_id         string                   id of the corresponding AbstractECU
            Output: -
        '''
        RegularApplicationLayer.__init__(self, sim_env, ecu_id)
        self._sync = simpy.Store(self.sim_env, capacity=1)     
        self.start_times = []
        
        self.TESLA_SETUP_START_TIME = 5
        self.TESLA_SETUP_INTERVAL_TIME = 99999999
        

    def _main_receive(self):
        ''' infinitely waits for an incoming message and logs it once it arrives
            
            Input:    -
            Output:   -
        '''
        while True:
            # receive
            a = yield self.sim_env.process(self.comm_mod.receive_msg())
            [self.msg_id, self.msg_data] = [a[0], a[1]]
            
            # log received
            if self.msg_id: L().log(500, self.sim_env.now, self._ecu_id, [self.msg_id, self.msg_data])                           
     
    def _main_send(self, sending_action):
        ''' after the sending actions have been sorted they are all started in 
            an own process that times out for the defined interval and then
            sends the message 
            
            Input:    sending_action    SendingAction        current sending action
            Output:   -
        '''
        
        print("%s waiting for end of key exchange %s" % (self._ecu_id, sending_action.message_id))
        yield self.sim_env.process(self.comm_mod.notify_key_ex_complete(sending_action.message_id))
        self.comm_mod.set_up = True
       
        
        print("%s sending process for msg ID %s is running (time: %s)" % (self._ecu_id, sending_action.message_id, self.sim_env.now))
        
        cnt = 0
        while True:
            
            if self.message_number:
                if cnt == self.message_number:
                    return
            cnt += 1
            
            # Send message
            L().log(501, self.sim_env.now, self._ecu_id, sending_action.message_id, sending_action.data.get()) 
            self.sim_env.process(self.comm_mod.send_msg(self._ecu_id, sending_action.message_id, sending_action.data))

            # timeout fixed interval (use random value to avoid message loss due to parallel processes)
            yield self.sim_env.timeout(sending_action.interval * self._jitter * (1 + 0.000000000001 * random.random()))
                 
            
    
    def _trigger_tesla_sender_setup(self):
        ''' this method is started from the main process. It waits for
            a defined interval before it starts the setup process of the
            TESLA implementation (time synchronization, initial key exchange)s
            
            Input:  -
            Output: -
        '''
        # wait defined interval
        yield self.sim_env.timeout(self.TESLA_SETUP_START_TIME)      
          
        while True:            
            
            # run setup phase
            yield self.sim_env.process(self.comm_mod.run_setup_phase())
               
            # wait setup interval
            yield self.sim_env.timeout(self.TESLA_SETUP_INTERVAL_TIME)
               
     
    def main(self):
        ''' this method first starts the receiving process and then starts
            all defined sending processes after there specified start time passed
            Moreover it starts the process that executes the tesla setup phase
            
            Input:     -
            Output:    -
        '''
        # tesla setup
#         self.sim_env.process(self._trigger_tesla_sender_setup())
        
        # receive
        self.sim_env.process(self._main_receive())
        
        # start setup
        self.sim_env.process(self.comm_mod.run_setup_phase())
        
        # send
        if not self.sending_messages: return
        
        # start messages at its start time
        for message in self.sending_messages:                        
            self.sim_env.process(self._main_send(message))
            
        if False: yield 3

