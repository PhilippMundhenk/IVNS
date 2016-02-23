from components.base.automotive_component import AutomotiveComponent
import uuid

class AbstractBusMessage(AutomotiveComponent):
    ''' 
    This abstract class defines the interface of
    a Bus Message   
    '''
        
    MAX_DATAFIELD_SIZE = 0
    
    def __init__(self, sim_env=None, message_id=None, data=None, timestamp=None, sender_id=None):
        ''' Constructor
            
            Input:    sim_env        simpy.Environment        environment of this component
                      message_id     integer                  message identifier
                      data           object                   content of the message
                      timestamp      float                    time the message was generated
                      sender_id      string                   id of the sender
        '''
        AutomotiveComponent.__init__(self, sim_env)
        
        # parameter
        self.data = data
        self.message_identifier = message_id        
        self.timestamp = timestamp        
        self.sender_id = sender_id
        self.gw_id = None      
        
        # message length
        self._msg_length_in_bit = 0  
        
    @property
    
    def msg_length_in_bit(self):  
        self._msg_length_in_bit = 42 + (len(hex(ord(self.data))) - 2) * 8
        return self._msg_length_in_bit

class SegData(object):
    ''' 
    this class is used to wrap information. Its data field contains the
    content of the message while it s length determines the data size    
    '''
    def __init__(self, data, size, unique_id=uuid.uuid4()):
        ''' Constructor
            
            Input:    data         object/string/...        data of the message
                      size         float                    size of the data in frame
            Output:    -
        '''
        self._data = data
        self._size = int(size)

        self.padded_size = int(size)  # used for CAN FD padding
        self.sender_id = None  # will be added at segment layer
        self.unique_id = unique_id
        
        self.dest_id = None

    
    def get(self):
        ''' returns the content of this 
            data wrapper
            
            Input:     -
            Output:    object    content that was wrapped in this packet
        '''
        return self._data
    
    
    def mark_sender(self, sender_id):
        ''' defines the sender id
            
            Input:     sender_id    string    identifier of the message sender
            Output:    -
        '''
        self.sender_id = sender_id
    
    
    def __len__(self):
        if self._size < 0:
            return 0
        return self._size
    
    
    
    
    
    
    
    
