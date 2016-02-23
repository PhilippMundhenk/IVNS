import simpy
from tools.ecu_logging import ECULogger as L
from components.security.ecu.software.impl_app_layer_regular import RegularApplicationLayer
from testcases.utilities.archSaver import SaveRandom
import sys

class TlsTestApplicationLayer(RegularApplicationLayer):
    ''' This class implements a simple application 
        running on a specific ECU. It is a subclass of
        RegularApplicationLayer. So it is able to send defined
        sending actions
    '''
    CNT = 0
    def __init__(self, sim_env, ecu_id=-1):
        ''' Constructor
            
            Input:  sim_env        simpy.Environment        environment of this component
                    ecu_id         string                   id of the corresponding AbstractECU
            Output: -
        '''
        RegularApplicationLayer.__init__(self, sim_env, ecu_id)        
        self.sync = simpy.Store(self.sim_env, capacity=1)     
        
        
    def _main_send(self, sending_action):
        ''' after the sending actions have been sorted they are all started in 
            an own process that times out for the defined interval and then
            sends the message 
            
            Input:    sending_action    SendingAction        current sending action
            Output:   -
        '''
        TlsTestApplicationLayer.CNT += 1
        # 1. per stream wait until all finished messages received
        print("%s Initializing stream %s" % (TlsTestApplicationLayer.CNT, sending_action.message_id))
        self.sim_env.process(self.comm_mod.send_msg(self._ecu_id, sending_action.message_id, sending_action.data))
        yield self.sim_env.process(self.comm_mod.notify_receivers_ready(sending_action.message_id))
        
        # 2. start sending the stream        
        print("sending process for msg ID %s is running (time: %s)" % (sending_action.message_id, self.sim_env.now))
        
        
        
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
            yield self.sim_env.timeout(sending_action.interval * self._jitter * (1 + 0.000000000001 * SaveRandom().ran.random()))
           
     
    def main(self):
        ''' this method first starts the receiving process and then starts
            all defined sending processes after there specified start time passed
            
            Input:     -
            Output:    -
        '''
        
        # receive
        self.sim_env.process(self._main_receive())
        
        # send if defined
        if not self.sending_messages: return
        
        # determine starting times
        diffs = self._get_diffs(self.sending_messages)
        yield self.sim_env.timeout(self.sending_messages[0].start_time * self._jitter)
        self.sim_env.process(self._main_send(self.sending_messages[0]))
        
        # start messages at its start time
        for i in range(len(diffs)):                        
            yield self.sim_env.timeout(diffs[i] * self._jitter)
            self.sim_env.process(self._main_send(self.sending_messages[i + 1]))

    
    def _main_receive(self):
        ''' infinitely waits for an incoming message and logs it once it arrives
            
            Input:    -
            Output:   -
        '''
        
        while True:
            
            # receive
            result = yield self.sim_env.process(self.comm_mod.receive_msg())
            [self.msg_id, self.msg_data] = [result[0], result[1]]
            
            
    
