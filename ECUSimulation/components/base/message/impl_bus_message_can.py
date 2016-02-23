from components.base.message.abst_bus_message import AbstractBusMessage
from components.base.message.abst_segment_bus_message import AbstractSegmentBusMessage
from tools.ecu_logging import ECULogger as L

class CANMessage(AbstractBusMessage):
    ''' 
    This class is an abstract implementation of a CAN Message
    '''
    
    MAX_DATAFIELD_SIZE = 8
    
    def __init__(self, sim_env, message_id, data, timestamp, sender_id):
        ''' Constructor
            
            Input:    sim_env        simpy.Environment        environment of this component
                      message_id     integer                  message identifier
                      data           object                   content of the message
                      timestamp      float                    time the message was generated
                      sender_id      string                   id of the sender
        '''
        AbstractBusMessage.__init__(self, sim_env, message_id, data, timestamp, sender_id)
        self.message_identifier = message_id  # 11 Bits
        self.ide = 1  # 1 Bit
        self.r0 = 0  # 1 Bit 
        self.dlc = 4  # 4 Bits
        self.data = data  # 0 ... 64 Bits
        self.crc = 1  # 15 Bits
        self.crc_delimiter = 0  # 1 Bit
        self.ack_slot = 0  # 1 Bit IN can FD its 2 Bit
        self.ack_delimiter = 0  # 1 Bit
        self.eof = 0  # 7 Bits
        
        self._msg_length_in_bit = 42
        self.no_stuffing_bits = 0
        self.timestamp = timestamp
        
    @property
    
    def msg_length_in_bit(self):  
        ''' this is the length that is used by the CAN Bus
            to determine the size of the packet
            
            Input:   -
            Output:  size     integer    Size of this message segment in Bit        
        '''
        try:
            bit_rep = ""
            for i in self.data:            
                hec = hex(ord(i))        
                h_size = len(hec) * 2
                h = (bin(int(hec, 16))[2:]).zfill(h_size)
                bit_rep += h
            
            self._msg_length_in_bit = 42 + len(bit_rep) + self.no_stuffing_bits
            return self._msg_length_in_bit
        except:
            L().log_err(400)
    
class CANSegMessage(AbstractSegmentBusMessage):
    ''' 
    This class is an abstract implementation of a segmentable CAN Message
    '''   
    
    MAX_DATAFIELD_SIZE = 8
    
    def __init__(self, sim_env, message_id, data, timestamp, sender_id):
        ''' Constructor
            
            Input:    sim_env        simpy.Environment        environment of this component
                      message_id     integer                  message identifier
                      data           object                   content of the message
                      timestamp      float                    time the message was generated
                      sender_id      string                   id of the sender
        '''
        AbstractSegmentBusMessage.__init__(self, sim_env, message_id, data, timestamp, sender_id)
        self.message_identifier = message_id  # 11 Bits
        self.ide = 1  # 1 Bit
        self.r0 = 0  # 1 Bit 
        self.dlc = 4  # 4 Bits
        self.data = data  # 0 ... 64 Bits
        self.crc = 1  # 15 Bits
        self.crc_delimiter = 0  # 1 Bit
        self.ack_slot = 0  # 1 Bit IN can FD its 2 Bit
        self.ack_delimiter = 0  # 1 Bit
        self.eof = 0  # 7 Bits

        self._msg_length_in_bit = 42
        self.no_stuffing_bits = 0
        self.timestamp = timestamp
        
    @property
    
    def msg_length_in_bit(self):
        ''' this is the length that is used by the CAN Bus
            to determine the size of the packet
            
            Input:   -
            Output:  size     integer    Size of this message segment in Bit        
        '''  
        bit_rep = ""        
        if self.seg_type == 0:  # single frame
            bit_rep = len(self.data) * 8
        
        if self.seg_type == 1:  # then this is a first frame 
            bit_rep = 6 * 8 + 2 * 8  # 2 control bytes, also count for the length
            
        if self.seg_type == 2:  # then this is a consecutive frame 
            try:
                len(self.data)
            except:
                self.data.size = 0
                    
            bit_rep = len(self.data) * 8 + 8  # 1 Byte Index and control
                
        self._msg_length_in_bit = 42 + bit_rep + self.no_stuffing_bits
        return self._msg_length_in_bit
    
            
