import simpy
from components.base.ecu.software.abst_application_layer import AbstractApplicationLayer
from components.base.message.abst_bus_message import SegData
import uuid
from tools.ecu_logging import ECULogger as L
import random

class RegularApplicationLayer(AbstractApplicationLayer):
    ''' 
    This class implements an Application that sends defined Data once 
    in a specific interval starting at a defined start time
    '''
    

    def __init__(self, sim_env, ecu_id=-1):
        ''' Constructor
            
            Input:    sim_env    simpy.Environment        environment of this component
                      ecu_id     string                   id of the corresponding AbstractECU
            Output:   -
        '''
        AbstractApplicationLayer.__init__(self, sim_env, ecu_id)
        
        # messages to send
        self.sending_messages = []
        
        # helper
        self._sync = simpy.Store(self.sim_env, capacity=1)             
        self._period_cnt = {}
        self._jitter = 1.0
        self.message_number = False
          
            
    def set_max_message_number(self, nr_messages):
        ''' sets the number of messages that are sent by this ecu per
            stream
        
            Input:    nr_messages    int    number of messages sent
            Output:    -
        '''
        self.message_number = nr_messages
    
    def add_sending(self, start_time, interval, message_id, data, data_length):
        ''' this method adds a new sending action to this application layer. 
            Then the message will start sending messages in the defined interval
            starting at the specified start_time
            
            Input:  start_time    float            time at which the first message is sent
                    interval      float            period within which the messages are sent
                    message_id    integer          message identifier of the messages that are sent
                    data          object/..        content of the messages that are sent
                    data_length   float            size of one message
            Output: -        
        '''
        
        # create message
        message = SegData(data, data_length)
        
        # add & sort message
        self.sending_messages.append(SendingAction(start_time, interval, message_id, message))
        self.sending_messages.sort(key=lambda x: x.start_time)
        self._period_cnt[self.sending_messages[-1].id] = 0
        
    
    def _main_receive(self):
        ''' infinitely waits for an incoming message and logs it once it arrives
            
            Input:    -
            Output:   -
        '''
        
        while True:
            
            # receive
            [self.msg_id, self.msg_data] = yield self.sim_env.process(self.comm_mod.receive_msg())
            
            # log received
            if self.msg_id: L().log(500, self.sim_env.now, self._ecu_id, [self.msg_id, self.msg_data])                           
           
      
    def _main_send(self, sending_action):
        ''' after the sending actions have been sorted they are all started in 
            an own process that times out for the defined interval and then
            sends the message 
            
            Input:    sending_action    SendingAction        current sending action
            Output:   -
        '''
        
        print("Sending stream %s" % sending_action.message_id)
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
            yield self.sim_env.timeout(sending_action.interval * self._jitter * (1 + 0.000000000001 * random.random()))
           
     
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
    
    
    def _get_diffs(self, send_action_list):
        ''' returns the differnces between the n th element of     
            the list assuming that the list was sorted beforehand
        
            Input:     send_action_list    list         list of Sending actions
            Output:    diff_list           list         derivation of the starting times, so the differences between two neighboring elements 
         '''           
        diff_list = []
        for i in range(len(send_action_list)):
            k = len(send_action_list) - i - 1
            if k == 0: break            
            cur_1 = send_action_list[k].start_time
            cur_2 = send_action_list[k - 1].start_time
            diff = cur_1 - cur_2
            diff_list.append(diff)
        return diff_list[::-1]

class SendingAction(object):
    '''
    saves information about a sending action. I.e. an 
    action defining the first sending time, the sending period and
    the content sent of a series of messages
    '''
    def __init__(self, start_time, interval, message_id, data):
        ''' Constructor
        
            Input:  start_time    float            time at which the first message is sent
                    interval      float            period within which the messages are sent
                    message_id    integer          message identifier of the messages that are sent
                    data          SegData          messages that are sent
            Output: -
        
        '''
        self.start_time = start_time
        self.interval = interval
        self.message_id = message_id
        self.data = data
        self.id = uuid.uuid4()


        


