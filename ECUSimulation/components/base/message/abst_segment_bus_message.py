from components.base.message.abst_bus_message import AbstractBusMessage


class AbstractSegmentBusMessage(AbstractBusMessage):
    ''' 
    This abstract class defines the interface of
    a Bus Message
    '''
    MAX_DATAFIELD_SIZE = 0
    
    def __init__(self, sim_env, message_id, data, timestamp, sender_id):
        ''' Constructor
            
            Input:    sim_env        simpy.Environment        environment of this component
                      message_id     integer                  message identifier
                      data           object                   content of the message
                      timestamp      float                    time the message was generated
                      sender_id      string                   id of the sender
        '''
        AbstractBusMessage.__init__(self, sim_env, message_id, data, timestamp, sender_id)
        
        self.expected_size = 0  # at max 4095 Byte!
        self.seg_type = 0  # 4 bit
        self.seg_index = 0  # 
                                        # data field indicating size not bigger than 4095
        # First frame has 12 bits for size indicator
        #             has 6 byte for data
        self._msg_length_in_bit = 0
        
        


    
        

