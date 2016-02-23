import math

from components.base.ecu.software.abst_comm_layers import AbstractTransportLayer
from components.base.message.abst_bus_message import SegData
import config.timing_registration as time
from tools.general import General as G
import uuid


class StdTransportLayer(AbstractTransportLayer):
    ''' 
    This class implements the Transport Layer for
    the implementation of a secure Communication 
    Module. It transmits message as a whole not in segments
    '''
    
    def __init__(self, sim_env, test=None):
        ''' Constructor
            
            Input:    sim_env          simpy.Environment                environment of this component                      
            Output:   -
        '''
        AbstractTransportLayer.__init__(self, sim_env, test=test)

        # project parameter
        self.STDTL_SEND_PROCESS = time.STDTL_SEND_PROCESS
        self.STDTL_RECEIVE_PROCESS = time.STDTL_RECEIVE_PROCESS

    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        self.settings['t_send_process'] = 'STDTL_SEND_PROCESS'
        self.settings['t_receive_process'] = 'STDTL_RECEIVE_PROCESS'

    
    def send_msg(self, sender_id, message_id, message_data):
        ''' gets a message of no matter which size and 
            sends it to its destination 
            wraps the message in a object of class MessageClass and forwards it
            as whole to the next lower layer adding a timeout
            
            Input:  sender_id      string        id of the sending component
                    message_id     integer       id of the message to be sent
                    message        object        Message that will be send on to the datalink layer
            Output:    -
        '''
        
        # wrap message
        message = self.MessageClass(self.sim_env, message_id, message_data, self.sim_env.now, sender_id)	

        # wait 
        if self._process_timeout_needed(): yield self.sim_env.timeout(self.STDTL_SEND_PROCESS * self._jitter)	

        # put it on datalink layer
        yield self.sim_env.process(self.datalink_lay.put_msg(message))

    
    def receive_msg(self):
        ''' receives segments from the communication module means datalink 
            layer puts them together and then returns it to the application 
            layer once it demands it
        
            Input:     -
            Output:    message_data         object         Message that was sent on communication layer of sender side
                       message_id           integer        message identifier of the received message            
        '''
        
        # pull message from datalink layer
        message = yield self.sim_env.process(self.datalink_lay.pull_msg()) 
        
        # wait
        if self._process_rec_timeout_needed(): yield self.sim_env.timeout(self.STDTL_RECEIVE_PROCESS * self._jitter)
            
        # received message was erroneous 
        if(message == None): return [None, None]
        
        # push message to application layer
        return [message.message_identifier, message.data] 

    
    def _process_rec_timeout_needed(self):
        ''' true if there is time needed to process this
            message on this layer upon receiving
        
            Input:    -    
            Output:   bool    boolean    True if there is time needed for processing
        '''
        if self.STDTL_RECEIVE_PROCESS != 0:
            G().to_t(self.sim_env, self.STDTL_RECEIVE_PROCESS * self._jitter, 'STDTL_RECEIVE_PROCESS', self.__class__.__name__, self)
            return True
        return False

    
    def _process_timeout_needed(self):
        ''' true if there is time needed to process this
            message on this layer
        
            Input:    -    
            Output:   bool    boolean    True if there is time needed for processing
        '''
        if self.STDTL_SEND_PROCESS != 0:
            G().to_t(self.sim_env, self.STDTL_SEND_PROCESS * self._jitter, 'STDTL_SEND_PROCESS', self.__class__.__name__, self)
            return True
        return False
            
class SegmentTransportLayer(AbstractTransportLayer):
    ''' 
    This class implements the Transport Layer for
    the implementation of a secure Communication 
    Module assuming that SEPARABLE data is transmitted 
    (i.e. Strings, hex-Strings, bit-Strings, ...)
    '''
    
    def __init__(self, sim_env, MessageClass):
        ''' Constructor
            
            Input:    sim_env          simpy.Environment                environment of this component       
                      MessageClass     MessageClass                     class of the message that is used to wrap the messages
            Output:   -
        '''
        AbstractTransportLayer.__init__(self, sim_env)
        
        # initialize
        self.receiving_buffer = []  # list of [msg_identifier, msg_sticked_together] ->consciously not using simpy queue, no blocking when using this implementation
        self.buffer_receiver = {}  # key = str([msg_identifier, msg_sticked_together]) / str([sender_id, message_id])
        self.rec_msgs_expected_size = {}  # key = str([sender_id, message_id]) / expected msg size 
        self.rec_msg = {}  # key = str([sender_id, message_id]) / msg sticked together
        self.set_settings()
        
        # project parameter
        self.SEGTL_SEND_PROCESS = time.SEGTL_SEND_PROCESS
        self.SEGTL_RECEIVE_PROCESS = time.SEGTL_RECEIVE_PROCESS

    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''     
        self.settings = {}
        
        self.settings['t_send_process'] = 'SEGTL_SEND_PROCESS'
        self.settings['t_receive_process'] = 'SEGTL_RECEIVE_PROCESS'

    
    def send_msg(self, sender_id, message_id, message, timing=False):
        ''' gets a message of no matter which size, segments it and 
            sends it to its destination. Assumes that AbstractSegmentBusMessage 
            is the message  given as MessageClass
        
            Input:  sender_id      string        id of the sending component
                    message_id     integer       id of the message to be sent
                    message        object        Message that will be send on to the datalink layer
            Output:    -
        '''
        # give each message an own id
        message.unique_id = uuid.uuid4()
        
        # variant
        if not timing: timing = self.SEGTL_SEND_PROCESS
        
        # timeout  
        time_val = self._timeout_sending(timing, message)        
        if time_val: yield self.sim_env.timeout(time_val * self._jitter)
        
        # no segmentation needed
        if self._segmentation_needed(message): yield self.sim_env.process(self._send_unsegmented(message_id, message, sender_id))
             
        # segmentation needed            
        else: yield self.sim_env.process(self._send_segmented(message, message_id, sender_id))

    
    def receive_msg(self):
        ''' receives segments from the communication module i.e. the transport layer puts them together and 
            then returns it to the application layer if it asks for it.
            This method receives all messages and saves them according to their sender and their content. Once
            all segments of a message are received this method returns it to the appliaction layer
            
            Input:     -
            Output:    message_data         object         Message that was sent on communication layer of sender side
                       message_id           integer        message identifier of the received message        
        '''
        
        # return message from receive buffer
        if(len(self.receiving_buffer) != 0): return self._get_next_received()
        
        # receive next
        msg_segment = 0
        
        while msg_segment != None:
            
            # receive frame
            msg_segment = yield self.sim_env.process(self.datalink_lay.pull_msg())         
            key_1 = str([msg_segment.sender_id, msg_segment.message_identifier, msg_segment.unique_id])
            
            # process the frame according to type            
            self._process_frame_type(msg_segment, key_1)
                        
            # message length as proposed -> end 
            self._try_expand_length(msg_segment)
            
            # return the next frame to application layer
            if(len(self.receiving_buffer) != 0):
                val, time_value = self._receive_frame_for_app()        
                if time_value != 0: yield self.sim_env.timeout(time_value * self._jitter)
                return val
        
        # message None
        return [None, None]

    def _receive_frame_for_app(self):
        ''' returns the next frame that is available and completely 
            received (all segments)
            
            Input:     -
            Output:    next_message    message    the whole received message (so the object sent)
                       time_value      float      time it takes to receive the message
        
        '''
        next_message = self._get_next_available()                
        
        time_value = time.call(self.SEGTL_RECEIVE_PROCESS, len(next_message[1]), self.MessageClass.MAX_DATAFIELD_SIZE)
        if time_value != 0:
            G().to_t(self.sim_env, time_value * self._jitter, 'REC_MSG', self.__class__.__name__, self)
            
        return next_message, time_value
            
    
    def _extract_first_frame(self, message, message_id, sender_id):
        ''' creates the first frame of the message as it is defined in the
            ISO Standard
            
            Input:  message       object     message to be sent
                    message_id    integer    message id to be sent
                    sender_id     string     id of the sender
            Output: -        
        '''
        cur_snip = message[:self.MessageClass.MAX_DATAFIELD_SIZE - 2]
        msg_segment = self.MessageClass(self.sim_env, message_id, cur_snip, self.sim_env.now, sender_id)
        msg_segment.seg_type = 1  # indicates first frame
        msg_segment.expected_size = len(message)
        return msg_segment
        
    
    def _extract_consecutive_frame(self, message, message_id, sender_id, i):
        ''' creates a consecutive frame of the message as it is defined in the
            ISO Standard
            
            Input:  message       object     message to be sent
                    message_id    integer    message id to be sent
                    sender_id     string     id of the sender
                    i             integer    sequence number of the current snippet
            Output: -        
        '''
        cur_snip = message[(self.MessageClass.MAX_DATAFIELD_SIZE - 2) + (i - 1) * (self.MessageClass.MAX_DATAFIELD_SIZE - 1) :\
                                    2 * (self.MessageClass.MAX_DATAFIELD_SIZE - 2) + (i - 1) * (self.MessageClass.MAX_DATAFIELD_SIZE - 1) + 1]
        msg_segment = self.MessageClass(self.sim_env, message_id, cur_snip, self.sim_env.now, sender_id)
        msg_segment.seg_type = 2  # indicates first frame
        msg_segment.seg_index = i - 1
        return msg_segment
        
    
    def _extract_last_frame(self, message, message_id, sender_id, i):
        ''' creates a last frame of the message as it is defined in the
            ISO Standard
            
            Input:  message       object     message to be sent
                    message_id    integer    message id to be sent
                    sender_id     string     id of the sender
                    i             integer    sequence number of the current snippet
            Output: -        
        '''
        cur_snip = message[(self.MessageClass.MAX_DATAFIELD_SIZE - 2) + (i - 1) * (self.MessageClass.MAX_DATAFIELD_SIZE - 1) :]   
        msg_segment = self.MessageClass(self.sim_env, message_id, cur_snip, self.sim_env.now, sender_id)
        msg_segment.seg_type = 2  # indicates first frame
        msg_segment.seg_index = i - 1
        
        return msg_segment

    
    def _get_next_available(self):
        ''' returns the next element that was received as
            a whole
            
            Input:     -
            Output:    val    object    the message that was received 
        '''
        try:
            val = self._get_next_received()
            self.rec_msgs_expected_size.pop(self.buffer_receiver[str(val)], None)
            self.rec_msg.pop(self.buffer_receiver[str(val)], None)
        except:
            pass
        return val

    
    def _get_next_received(self):
        ''' returns the next element that was received as
            a whole
            
            Input:     -
            Output:    val    object    the message that was received 
        '''
        if(len(self.receiving_buffer) != 0):
            val = self.receiving_buffer[::-1].pop()
            self.receiving_buffer.remove(val)
            return [val[0], val[1]]
        else:
            return [None, None]
    
    
    def _pad_to_canfd(self, orig_message):
        ''' the Can FD standard only allows certain sizes for the messages to
            be sent. Therefor all byte segments that are transmitted need to be padded
            to those lengths
            
            Input:     message    object    message segment that needs to be sent
            Output:    msg        object    message segment with the correct padded size
        '''
        allowed_steps = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]
        
        # handle string
        if (isinstance(orig_message, str)):
            message = self._pad_string(orig_message, allowed_steps)
            if message: return message
            
        # handle different type
        message = self._pad_usual(orig_message, allowed_steps)
        if message: return message
        
        return orig_message
    
    
    def _pad_usual(self, message, allowed_steps):
        ''' pads a message to the next higher size provided in 
            allowed_steps
            
            Input:     message    SegData    data of wrong size
            Output:    message    SegData     data of allowed size
        '''
        try:
            if len(message) not in allowed_steps:
                for i in allowed_steps:
                    if i > len(message):
                        message.padded_size = i 
                        return message
        except:
            return False
        return False

    
    def _pad_string(self, message, allowed_steps):
        ''' pads a message to the next higher size provided in 
            allowed_steps
            
            Input:     message    string    string of wrong size
            Output:    message    SegData   data of allowed size
        '''
        try:
            if len(message) not in allowed_steps:
                for i in allowed_steps:
                    if i > len(message):
                        msg = SegData(message, len(message))
                        msg.padded_size = i
                        return msg
        except:
            return False
        return False
    
    
    def _process_frame_type(self, message_segment, key_1):
        ''' depending on the type of received element the messages
            are saved to the corresponding receiving dictionaries
            
            Input:  message_segment      CANFDSegMessage    segment to be saved in the specified dictionary
                    key_1                string             id for the dictionary
            Output
        '''
        
        # received a single frame
        if(message_segment.seg_type == 0):   
            self.receiving_buffer.append([message_segment.message_identifier, message_segment.data])
            
        # received first frame
        if(message_segment.seg_type == 1):                
            self.rec_msgs_expected_size[key_1] = message_segment.expected_size  # = expected_data_len
            self.rec_msg[key_1] = message_segment.data
            
        # receive consecutive frame            
        if(message_segment.seg_type == 2):
            try:
                self.rec_msg[key_1] = self.rec_msg[key_1] + message_segment.data  # = expected_data_len
            except:           
                self.rec_msg[key_1] = message_segment.data

    
    def _segmentation_needed(self, message):
        ''' true if segmentation is needed for this message else false
            This depends on the size of the message
            
            Input:     message    object     message that needs to be sent
            Output:    bool       boolean    true if segmentation is needed
        '''
        if (len(message) < self.MessageClass.MAX_DATAFIELD_SIZE):
            return True
        else:
            return False

    
    def _send_unsegmented(self, message_id, message, sender_id):
        ''' the message is simply forwarded to the datalink layer. It is
            only padded to fit the CANFD frame and is then sent
            
            Input:  message       object     message to be sent
                    message_id    integer    message id to be sent
                    sender_id     string     id of the sender
                    
            Output: -
        
        '''
        
        # pad data to fit CAN FD frame
        message = self._pad_to_canfd(message)
        try: message.mark_sender(sender_id)
        except: pass
        
        # wrap message in SegMessage
        msg_segment = self.MessageClass(self.sim_env, message_id, message, self.sim_env.now, sender_id)
        msg_segment.seg_type = 0
        
        # put on data link layer
        yield self.sim_env.process(self.datalink_lay.put_msg(msg_segment))
           
    
    def _send_segmented(self, message, message_id, sender_id):
        ''' send a message by segmenting it into multiple frames of
            the size to fit a CANFD frame. Thereby the ISO 15765-2
            standard was implemented
            
            Input:  message       object     message to be sent
                    message_id    integer    message id to be sent
                    sender_id     string     id of the sender
                    
            Output: -            
        '''
        # calculate number of frames
        no_msgs = math.ceil(((len(message) - (self.MessageClass.MAX_DATAFIELD_SIZE - 2)) / (self.MessageClass.MAX_DATAFIELD_SIZE - 1))) + 1            
        
        for i in range(no_msgs):
            
            # send First frame message bytes 0..5
            if i == 0:
                msg_segment = self._extract_first_frame(message, message_id, sender_id)
                            
            # send consecutive frame
            elif i != no_msgs - 1:
                msg_segment = self._extract_consecutive_frame(message, message_id, sender_id, i)
            
            # send last frame
            else:
                msg_segment = self._extract_last_frame(message, message_id, sender_id, i)
            
            # put message on data link layer
            msg_segment.unique_id = message.unique_id
            yield self.sim_env.process(self.datalink_lay.put_msg(msg_segment))              
     
    
    def _timeout_sending(self, timing, message):
        ''' timeout that is needed to send this message on this layer
        
            Input:  timing:    boolean    optional value for FakeSegmentTransportLayer
                    message    object     message that needs to be sent
            Output: time_val    float     float if this value is not zero else False            
        '''
        
        time_val = time.call(timing, len(message), self.MessageClass.MAX_DATAFIELD_SIZE)        
        
        if time_val != 0:
            G().to_t(self.sim_env, time_val * self._jitter, 'SEND_MSG', self.__class__.__name__, self)
            return time_val
        return False
     
    
    def _try_expand_length(self, message_segment):
        ''' adds the new message segment to the corresponding dictionary
            if this frame was the last frame then the message waas fully received
            and can be put into the receiving buffer
        
            Input     message_segment    CANSegMessage    current segment received
            Output    - 
            
        '''
        try:
            key_1 = str([message_segment.sender_id, message_segment.message_identifier, message_segment.unique_id])
            key_2 = str([message_segment.message_identifier, self.rec_msg[key_1]])
            
            if self.rec_msgs_expected_size[key_1] == len(self.rec_msg[key_1]):                                                
                self.buffer_receiver[key_2] = key_1          
                self.receiving_buffer.append(eval(key_2))

        except:
            pass
    
class FakeSegmentTransportLayer(SegmentTransportLayer):
    ''' this class does no real segmentation it simply sends the 
    data to be sent in the first message
    the following messages are basically empty and ground on the 
    information provided in the size field of SegData Object that 
    wraps the data to be sent
    
    ATTENTION:  MESSAGES (or there data!) SENT THROUGH THIS MODULE HAVE TO SPECIFY THE __len__ 
                OPERATOR WHICH RETURNS THE SIZE OF THE MESSAGE TO BE SENT
                i.e. should be e.g. wrapped in a SegData(msg, msg_size) object
    
    e.g.
    def __len__(self):
        size = 1000                                # Byte
        return size
    '''
    
    def __init__(self, sim_env, MessageClass):
        ''' Constructor
            
            Input:    sim_env          simpy.Environment                environment of this component       
                      MessageClass     MessageClass                     class of the message that is used to wrap the messages
            Output:   -
        '''
        SegmentTransportLayer.__init__(self, sim_env, MessageClass)
        
        # initial parameters
        self.rec_len = {}
        self.set_settings()

        # project Parameter 
        self.FSEGTL_RECEIVE_PROCESS = time.FSEGTL_RECEIVE_PROCESS
        self.FSEGTL_SEND_PROCESS = time.FSEGTL_SEND_PROCESS

    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''  
        self.settings = {}
        
        self.settings['t_send_process'] = 'FSEGTL_SEND_PROCESS'
        self.settings['t_receive_process'] = 'FSEGTL_RECEIVE_PROCESS'

    
    def receive_msg(self):
        ''' receives segments from the communication module means datalink 
            layer puts them together and then returns it to the application 
            layer once it demands it
        
            Input:     -
            Output:    message_data         object         Message that was sent on communication layer of sender side
                       message_id           integer        message identifier of the received message            
        '''
  
        # return next message to app layer
        if(len(self.receiving_buffer) != 0):
            return self._get_next_received()
        
        # receive element
        msg_segment = 0      
        while msg_segment != None:
                        
            # receive frame
            msg_segment = yield self.sim_env.process(self.datalink_lay.pull_msg()) 

            key_1 = str([msg_segment.sender_id, msg_segment.message_identifier, msg_segment.unique_id])
            
            # process the frame
            self._process_frame_type(msg_segment, key_1)
            
            # message length as proposed -> end 
            self._try_expand_length(msg_segment)
            
            # return the next frame
            if(len(self.receiving_buffer) != 0):
                val = self._get_next_available()               
                time_val = time.call(self.FSEGTL_RECEIVE_PROCESS, len(val[1]), self.MessageClass.MAX_DATAFIELD_SIZE)
                if time_val != 0:
                    G().to_t(self.sim_env, time_val, 'FSEGTL_RECEIVE_PROCESS', self.__class__.__name__, self)
                    self.sim_env.timeout(time_val)
                return val                
                  
        return [None, None]
    
    
    def _process_frame_type(self, message_segment, key_1):
        ''' depending on the type of received element the messages
            are saved to the corresponding receiving dictionaries
            
            Input:  message_segment      CANFDSegMessage    segment to be saved in the specified dictionary
                    key_1                string             id for the dictionary
            Output
        '''
        
        # receive single frame
        if(message_segment.seg_type == 0):   
            self.receiving_buffer.append([message_segment.message_identifier, message_segment.data])

        # receive first frame
        if(message_segment.seg_type == 1):                
            self.rec_msgs_expected_size[key_1] = message_segment.expected_size  # = expected_data_len
            self.rec_msg[key_1] = message_segment.data
            self.rec_len[key_1] = self.MessageClass.MAX_DATAFIELD_SIZE - 2
             

        # receive consecutive frame            
        if(message_segment.seg_type == 2):
            try:
                self.rec_len[key_1] = self.rec_len[key_1] + len(message_segment.data)
            except:           
                self.rec_msg[key_1] = message_segment.data
    
    
    def send_msg(self, sender_id, message_id, message):
#         try:
#             print("TL ->Sending message %s to %s" % (message.get(), message.sender_id))
#         except:
#             pass
        yield self.sim_env.process(SegmentTransportLayer.send_msg(self, sender_id, message_id, message, timing=self.FSEGTL_SEND_PROCESS))

    
    def _get_next_available(self):
        ''' returns the next element that was received as
            a whole
            
            Input:     -
            Output:    val    object    the message that was received 
        '''
        try:
            val = self._get_next_received()
            self.rec_msgs_expected_size.pop(self.buffer_receiver[str(val)], None)
            self.rec_msg.pop(self.buffer_receiver[str(val)], None)
        except:
            pass
        try:            
            self.rec_msgs_expected_size.pop(self.buffer_receiver[str(val)], None)
            self.rec_len.pop(self.buffer_receiver[str(val)], None)
            
            del self.rec_len[self.buffer_receiver[str(val)]]
        except:
            pass
        
        try:
            # remove the element
            del self.buffer_receiver[str(val)]
        except:
            pass
        return G().val_log_info(val, 802, val)
    
    
    def _send_segmented(self, message, message_id, sender_id):
        ''' send a message by segmenting it into multiple frames of
            the size to fit a CANFD frame. Thereby the ISO 15765-2
            standard was implemented
            
            Input:  message       object     message to be sent
                    message_id    integer    message id to be sent
                    sender_id     string     id of the sender
                    
            Output: -            
        '''
        # count sent data
        no_msgs = math.ceil(((len(message) - (self.MessageClass.MAX_DATAFIELD_SIZE - 2)) / (self.MessageClass.MAX_DATAFIELD_SIZE - 1))) + 1            
        self.sent_data = 0
        
        for i in range(no_msgs):
                        
            # send First frame (bytes 0..5 with original message
            #                   in CAN FD 0...5*8 = 0...40 bytes)
            if i == 0:
                msg_segment = self._extract_first_frame(message, message_id, sender_id)
                self.sent_data = self.sent_data + self.MessageClass.MAX_DATAFIELD_SIZE - 2

            # send consecutive frame
            elif i != no_msgs - 1:
                msg_segment = self._extract_consecutive_frame(message, message_id, sender_id, i)
                self.sent_data = self.sent_data + len(msg_segment.data)
            
            # send last frame
            else:
                if  len(message) - self.sent_data < 0: self.sent_data = len(message)
                msg_segment = self._extract_last_frame(message, message_id, sender_id, i, len(message) - self.sent_data)
            
            # pad message to can_fd
            msg_segment.data = self._pad_to_canfd(msg_segment.data)  # padding can FD to correct size

            try: msg_segment.data.unique_id = message.unique_id
            except: pass
            
            msg_segment.unique_id = message.unique_id
            yield self.sim_env.process(self.datalink_lay.put_msg(msg_segment))
       
    
    def _try_expand_length(self, msg_segment):
        ''' adds the new message segment to the corresponding dictionary
            if this frame was the last frame then the message waas fully received
            and can be put into the receiving buffer
        
            Input     message_segment    CANSegMessage    current segment received
            Output    - 
            
        '''
        try:
            key_1 = str([msg_segment.sender_id, msg_segment.message_identifier, msg_segment.unique_id])
            key_2 = str([msg_segment.message_identifier, self.rec_msg[key_1]])
            
            if self.rec_msgs_expected_size[key_1] == self.rec_len[key_1]:                                                
                self.buffer_receiver[key_2] = key_1
                self.receiving_buffer.append([msg_segment.message_identifier, self.rec_msg[key_1]])
        except:
            pass
    
    
    def _extract_first_frame(self, message, message_id, sender_id):
        ''' creates the first frame of the message as it is defined in the
            ISO Standard
            
            Input:  message       object     message to be sent
                    message_id    integer    message id to be sent
                    sender_id     string     id of the sender
            Output: -        
        '''
        msg_segment = self.MessageClass(self.sim_env, message_id, message, self.sim_env.now, sender_id)
        msg_segment.seg_type = 1  # indicates first frame
        msg_segment.expected_size = len(message)
        return msg_segment
    
    
    def _extract_consecutive_frame(self, message, message_id, sender_id, i):
        ''' creates a consecutive frame of the message as it is defined in the
            ISO Standard
            
            Input:  message       object     message to be sent
                    message_id    integer    message id to be sent
                    sender_id     string     id of the sender
            Output: -        
        '''
        cur_snip = SegData("0" * (self.MessageClass.MAX_DATAFIELD_SIZE - 1), (self.MessageClass.MAX_DATAFIELD_SIZE - 1))
        msg_segment = self.MessageClass(self.sim_env, message_id, cur_snip, self.sim_env.now, sender_id)
        msg_segment.seg_type = 2  # indicates cons frame
        msg_segment.seg_index = i - 1
        return msg_segment

    
    def _extract_last_frame(self, message, message_id, sender_id, i, no_end):
        ''' creates the last frame of the message as it is defined in the
            ISO Standard
            
            Input:  message       object     message to be sent
                    message_id    integer    message id to be sent
                    sender_id     string     id of the sender
            Output: -        
        '''
        cur_snip = SegData("0" * no_end, no_end)
        msg_segment = self.MessageClass(self.sim_env, message_id, cur_snip, self.sim_env.now, sender_id)
        msg_segment.seg_type = 2  # indicates last frame
        msg_segment.seg_index = i - 1
        
        return msg_segment
