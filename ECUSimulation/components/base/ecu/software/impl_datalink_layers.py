from components.base.ecu.software.abst_comm_layers import AbstractDataLinkLayer
import config.timing_registration as time
from tools.general import General as G
from tools.ecu_logging import ECULogger as L
from queue import PriorityQueue

class QueueElement(object):
    
    def __init__(self, message_id, message):
        self.message_identifier = message_id
        self.message = message
        
    def __lt__(self, other):        
        return self.message_identifier < other.message_identifier

class StdDatalinkLayer(AbstractDataLinkLayer):
    ''' This class implements the Datalink Layer of
        the implementation of a secure Communication 
        Module'''
        
    CNT = 0
    def __init__(self, sim_env):
        ''' Constructor
            
            Input:    sim_env              simpy.Environment                environment of this component
            Output:   -
        '''
        AbstractDataLinkLayer.__init__(self, sim_env)

        # set settings
        self.set_settings()
        self.transmit_buffer_size = 0
        
        # timing Parameter 
        self.STDDLL_RECEIVE_BUFFER = time.STDDLL_RECEIVE_BUFFER
        self.STDDLL_TRANSMIT_BUFFER = time.STDDLL_TRANSMIT_BUFFER
        self.STDDLL_BACKOFF_AFTER_COL = time.STDDLL_BACKOFF_AFTER_COL
        self.STDDLL_GET_MSG_PRIO = time.STDDLL_GET_MSG_PRIO

    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        self.settings['t_fill_receive_buffer'] = 'STDDLL_RECEIVE_BUFFER'
        self.settings['t_put_to_trasm_buffer'] = 'STDDLL_TRANSMIT_BUFFER'
        self.settings['t_backoff_after_col'] = 'STDDLL_BACKOFF_AFTER_COL'
        self.settings['t_get_msg_prio'] = 'STDDLL_GET_MSG_PRIO'

    
    def pull_msg(self):
        ''' this method waits until the receiving buffer is 
            filled by the connected transceiver. Once this is happening
            it is checked if the receiving buffer is already full. If that
            is not the case the message is processed and forwarded to
            the transport layer 
        
            Input:     - 
            Output:    message    object    message that was received and will be forwarded to transport layer
        '''  

        # wait for receiving
        message = yield self.controller.receive_buffer.get()
        
        # check 
        if self._wait_receive():        
            yield self.sim_env.timeout(self.STDDLL_RECEIVE_BUFFER * self._jitter)   
        
        return message
        
    
    def put_msg(self, message):
        ''' tries to put the message that was passed to the transmit buffer.
            Therefor it checks if the buffer is not full yet. Then it adds the 
            element to the buffer
            
            Input:     message    object        message that should be send over the bus
            Output:    -
        '''

        # transmit buffer full
        size_after_add, size_before_add = self._extract_sizes(message)
        if size_after_add > size_before_add:  return G().val_log_info(None, 801)
        
        # time to transmit
        if self._need_time_transmit(): yield self.sim_env.timeout(self.STDDLL_TRANSMIT_BUFFER * self._jitter)
            
        # add message to buffer
        self.controller.transmit_buffer.put(message)
        self.transmit_buffer_size += message.msg_length_in_bit / 8
        
    
    def process(self):
        ''' this method processes all messages that are in the transmit buffer
            once a message is in the buffer the message with the highest priority
            in the buffer is selected and then sent
        
            Input:     -
            Output:    -
        '''
        
        message = None
        while True:

            # send highest priority
            if(message == None):
                
                # grab message
                message = yield self.controller.transmit_buffer.get() 
                message = self._get_next_high_prio(message)
                
                # wait
                if self._need_time_message_priority():
                    yield self.sim_env.timeout(self.STDDLL_GET_MSG_PRIO * self._jitter)
                
                
            # channel free
            if self.physical_lay.bus_free(): 
                
                # try sending
                sending_ok = yield self.sim_env.process(self.physical_lay.put(message))  # send message and check if sending was successful, else resend
                if sending_ok: 
                    self.transmit_buffer_size -= message.msg_length_in_bit / 8
                    message = None
                    yield self.physical_lay.transceiver.connected_bus.sync_send.get()  # bus busy sending
                else: continue

            else:                
                
                # wait until free -> get notification from bus
                yield self.sim_env.process(self.physical_lay.wake_if_channel_free())
                StdDatalinkLayer.CNT += 1
                         
                # wait backoff time       
                backoff = time.call(self.STDDLL_BACKOFF_AFTER_COL, self.effective_bittime)
                G().to_t(self.sim_env, backoff, 'backoff', self.__class__.__name__, self)
                yield self.sim_env.timeout(backoff)

    
    def _extract_sizes(self, message):
        ''' extracts the message the buffer would have before the message
            is received and after it was received
        
            Input:     message            object    incoming message
            Output:    size_after_add     float     size of the buffer after the message was added
                       size_before_add    float     size of the buffer before the message was added
        '''
        size_after_add = self.controller.transmit_buffer.get_bytes() + (float(message.msg_length_in_bit) / 8.0)         
        size_before_add = self.controller.transmit_buffer.max_size
        return size_after_add, size_before_add
    
    
    def _get_next_high_prio(self, message):
        ''' get the message with the highest priority in the
            transmit buffer. Before that the new messaage is added
            back to the buffer
        
            Input:     message     object    currently received message
            Output:    message     object    message with highest priority in the transmit buffer
        '''
        
        # add new message
        self.controller.transmit_buffer.items.insert(0, message)
        
        # choose message with highest priority
        message = self._get_highest_prio_msg(self.controller.transmit_buffer.items)
        
        # remove it from transmit buffer
        try: self.controller.transmit_buffer.items.remove(message)
        except: L().log_traceback()
        
        # return found
        return message
           
         
    def _get_highest_prio_msg(self, message_list):
        ''' finds the message with the lowest message id
            in the list of messages and returns it 
        
            Input:    message_list    list        list of messages
            Output:   message         object      message with the highest priority in the buffer
        '''
        min_val = float("inf")
        message = None
        for cur_message in message_list:            
            if min_val > cur_message.message_identifier:
                min_val = cur_message.message_identifier
                message = cur_message
        return message            
    
    
    def _need_time_message_priority(self):
        ''' true if the message priority estimation needs time
            else false
            
            Input:    -
            Output:    bool    boolean    true if the message priority estimation needs time
        '''
        if self.STDDLL_GET_MSG_PRIO != 0:
            G().to_t(self.sim_env, self.STDDLL_GET_MSG_PRIO * self._jitter, 'STDDLL_GET_MSG_PRIO', self.__class__.__name__, self)
            return True
        return False
    
    
    def _need_time_transmit(self):
        ''' true if the transmit buffer needs a sending time
            else false
            
            Input:    -
            Output:    bool    boolean    true if the transmit buffer needs a sending time
        '''
        if self.STDDLL_TRANSMIT_BUFFER != 0:
            G().to_t(self.sim_env, self.STDDLL_TRANSMIT_BUFFER * self._jitter, 'STDDLL_TRANSMIT_BUFFER', self.__class__.__name__, self)
            return True
        return False
    
    def _wait_receive(self):
        ''' if the time to receive the message is zero this
            method is false. Otherwise it is true
            
            Input:     -
            Output:    bool    boolean    true if the time to receive the message is not zero
        '''
        if self.STDDLL_RECEIVE_BUFFER != 0:
            G().to_t(self.sim_env, self.STDDLL_RECEIVE_BUFFER * self._jitter, 'STDDLL_RECEIVE_BUFFER', self.__class__.__name__, self)
            return True
        return False

class RapidDatalinkLayer(AbstractDataLinkLayer):
    ''' This class implements the Datalink Layer that offers only
        admission to the transmit buffer elements. It maintains a 
        queue that is provided to the RapidCANBus. This Bus implementation
        has a deviation of about 3 bit times per message that was sent'''

    CNT = 0
    def __init__(self, sim_env):
        ''' Constructor
            
            Input:    sim_env              simpy.Environment                environment of this component
            Output:   -
        '''
        AbstractDataLinkLayer.__init__(self, sim_env)
        self._controller = None
        
        # set settings
        self.set_settings()
        self.transmit_buffer_size = 0
        
        # timing Parameter 
        self.STDDLL_RECEIVE_BUFFER = time.STDDLL_RECEIVE_BUFFER
        self.STDDLL_TRANSMIT_BUFFER = time.STDDLL_TRANSMIT_BUFFER
        self.STDDLL_BACKOFF_AFTER_COL = time.STDDLL_BACKOFF_AFTER_COL
        self.STDDLL_GET_MSG_PRIO = time.STDDLL_GET_MSG_PRIO
            
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        
        self.settings['t_fill_receive_buffer'] = 'STDDLL_RECEIVE_BUFFER'
        self.settings['t_put_to_trasm_buffer'] = 'STDDLL_TRANSMIT_BUFFER'
        self.settings['t_backoff_after_col'] = 'STDDLL_BACKOFF_AFTER_COL'
        self.settings['t_get_msg_prio'] = 'STDDLL_GET_MSG_PRIO'
    
    def pull_msg(self):
        ''' this method waits until the receiving buffer is 
            filled by the connected transceiver. Once this is happening
            it is checked if the receiving buffer is already full. If that
            is not the case the message is processed and forwarded to
            the transport layer 
        
            Input:     - 
            Output:    message    object    message that was received and will be forwarded to transport layer
        '''  

        # wait for receiving
        message = yield self._controller.receive_buffer.get()

        # check 
        if self._wait_receive():        
            yield self.sim_env.timeout(self.STDDLL_RECEIVE_BUFFER * self._jitter)   
        
        return message
        
    
    def put_msg(self, message):
        ''' puts the message into the buffer in a sorted way. Messages that arrived earlier
            and messaged that have a higher priority are further up front in the queue 
            
            Input:     message    object        message that should be send over the bus
            Output:    -
        '''        
        
        # transmit buffer full
        size_after_add, size_before_add = self._extract_sizes(message)
        if size_after_add > size_before_add:  return G().val_log_info(None, 801)
        
        # dummy
        if False: yield self.sim_env.timeout(0) 
        
        # pritoriy is lower if 0 is sent: 
        if isinstance(message.data.get(), str) and message.data.get().isdigit():
            preval = 0.001
        else: preval = 0
        
        self._controller.transmit_buffer.put(QueueElement(message.message_identifier + preval, message))
                
        # add message to buffer
        self.physical_lay.transceiver.connected_bus.add_willing(self)
        if len(self._controller.transmit_buffer.queue) == 1:
            self.physical_lay.transceiver.connected_bus.notify_bus()
            
    def first_queue_identifier(self):
        ''' this message returns the first message in the
            buffer queue. if no message is inside the buffer
            false is returned
            
            Input:    -
            Output:   priority    integer        priority of the queue or False
        '''
        
        # empty queue return False
        if not self._controller.transmit_buffer.queue: 
            return False        
        
        # return first element
        return self._controller.transmit_buffer.queue[0].message_identifier
        
    def _extract_sizes(self, message):
        ''' extracts the message the buffer would have before the message
            is received and after it was received
        
            ATTENTION: transmit buffer bytes not implemented
        
            Input:     message            object    incoming message
            Output:    size_after_add     float     size of the buffer after the message was added
                       size_before_add    float     size of the buffer before the message was added
        '''
        size_after_add = 0  # self._controller.transmit_buffer.get_bytes() + (float(message.msg_length_in_bit) / 8.0)         
        size_before_add = 0  # self._controller.transmit_buffer.max_size
        return size_after_add, size_before_add
    
    def process(self):
        yield self.sim_env.timeout(10)
    
    def _get_next_high_prio(self, message):
        ''' get the message with the highest priority in the
            transmit buffer. Before that the new messaage is added
            back to the buffer
        
            Input:     message     object    currently received message
            Output:    message     object    message with highest priority in the transmit buffer
        '''
        
        # add new message
        self._controller.transmit_buffer.items.insert(0, message)
        
        # choose message with highest priority
        message = self._get_highest_prio_msg(self._controller.transmit_buffer.items)
        
        # remove it from transmit buffer
        try: self._controller.transmit_buffer.items.remove(message)
        except: L().log_traceback()
        
        # return found
        return message
           
         
    def _get_highest_prio_msg(self, message_list):
        ''' finds the message with the lowest message id
            in the list of messages and returns it 
        
            Input:    message_list    list        list of messages
            Output:   message         object      message with the highest priority in the buffer
        '''
        min_val = float("inf")
        message = None
        for cur_message in message_list:            
            if min_val > cur_message.message_identifier:
                min_val = cur_message.message_identifier
                message = cur_message
        return message            
    
    
    def _need_time_message_priority(self):
        ''' true if the message priority estimation needs time
            else false
            
            Input:    -
            Output:    bool    boolean    true if the message priority estimation needs time
        '''
        if self.STDDLL_GET_MSG_PRIO != 0:
            G().to_t(self.sim_env, self.STDDLL_GET_MSG_PRIO * self._jitter, 'STDDLL_GET_MSG_PRIO', self.__class__.__name__, self)
            return True
        return False
    
    
    def _need_time_transmit(self):
        ''' true if the transmit buffer needs a sending time
            else false
            
            Input:    -
            Output:    bool    boolean    true if the transmit buffer needs a sending time
        '''
        if self.STDDLL_TRANSMIT_BUFFER != 0:
            G().to_t(self.sim_env, self.STDDLL_TRANSMIT_BUFFER * self._jitter, 'STDDLL_TRANSMIT_BUFFER', self.__class__.__name__, self)
            return True
        return False
    
    def _wait_receive(self):
        ''' if the time to receive the message is zero this
            method is false. Otherwise it is true
            
            Input:     -
            Output:    bool    boolean    true if the time to receive the message is not zero
        '''
        if self.STDDLL_RECEIVE_BUFFER != 0:
            G().to_t(self.sim_env, self.STDDLL_RECEIVE_BUFFER * self._jitter, 'STDDLL_RECEIVE_BUFFER', self.__class__.__name__, self)
            return True
        return False


    @property
    def controller(self):
        return self._controller
    
    @controller.setter
    def controller(self, value):
        if value == None: return
        self._controller = value
        self._controller.transmit_buffer = PriorityQueue()   
        
