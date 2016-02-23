from components.base.message.abst_bus_message import AbstractBusMessage
from components.base.message.abst_segment_bus_message import AbstractSegmentBusMessage
import math
from tools.ecu_logging import ECULogger as L
import uuid

class CANFDMessage(AbstractBusMessage):
    ''' 
    This class is an abstract implementation of a CAN Message
    '''    
    
    MAX_DATAFIELD_SIZE = 64
    
    def __init__(self, sim_env, message_id, data, timestamp, sender_id):
        ''' Constructor
            
            Input:    sim_env        simpy.Environment        environment of this component
                      message_id     integer                  message identifier
                      data           object                   content of the message
                      timestamp      float                    time the message was generated
                      sender_id      string                   id of the sender
        '''
        AbstractBusMessage.__init__(self, sim_env, message_id, data, timestamp, sender_id)
        
        self.sof = 1  # Start of Frame
        self.message_identifier = message_id  # 11 Bits
        self.srr = 1  # 1 Bit
        self.ide = 1  # 1 Bit
        self.identifier_extension = 18  # 18 Bits
        self.r1 = 1  # 1 Bit 
        self.edl = 1  # 1 Bits
        self.r0 = 1  # 1 Bit 
        self.brs = 1  # 1 Bit 
        self.esi = 1  # 1 Bit 
        
        self.dlc = 4  # 4 Bits        
        self.data = data  # 0 ... 64 Bytes
        
        self.crc = 1  # 21 Bits
        self.crc_delimiter = 0  # 1 Bit
        self.ack_slot = 2  # 1 Bit
        self.ack_delimiter = 0  # 1 Bit
        self.eof = 0  # 7 Bits
        
        self._msg_length_in_bit = 71
        self.no_stuffing_bits = 0
        self.timestamp = timestamp
        
        # CAUTION: The length of the data field of the message is still 
        #          8 Bytes! The only difference is that there are 64 Bytes
        #          in that 8 Bytes
        
    @property
    
    def msg_length_in_bit(self):  # as seen from Bus System
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
            
            self._msg_length_in_bit = 71 + math.ceil(len(bit_rep) / 8) + self.no_stuffing_bits
            return self._msg_length_in_bit
        except:
            L().log_err(400)
    
class CANFDSegMessage(AbstractSegmentBusMessage):
    ''' 
    This class is an abstract implementation of a segmentable CAN Message
    '''

    MAX_DATAFIELD_SIZE = 64
    IS_CAN_FD = True
    
    def __init__(self, sim_env, message_id, data, timestamp, sender_id):
        ''' Constructor
            
            Input:    sim_env        simpy.Environment        environment of this component
                      message_id     integer                  message identifier
                      data           object                   content of the message
                      timestamp      float                    time the message was generated
                      sender_id      string                   id of the sender
        '''
        AbstractSegmentBusMessage.__init__(self, sim_env, message_id, data, timestamp, sender_id)
        
        self.sof = 1  # Start of Frame
        self.message_identifier = message_id  # 11 Bits
        self.srr = 1  # 1 Bit
        self.ide = 1  # 1 Bit
        self.identifier_extension = 18  # 18 Bits
        self.r1 = 1  # 1 Bit 
        self.edl = 1  # 1 Bits
        self.r0 = 1  # 1 Bit 
        self.brs = 1  # 1 Bit 
        self.esi = 1  # 1 Bit 
        
        self.dlc = 4  # 4 Bits    
                    
        self.data = data  # 0 ... 64 Bytes
        
        self.crc = 1  # 15 Bits
        self.crc_delimiter = 0  # 1 Bit
        self.ack_slot = 2  # 1 Bit
        self.ack_delimiter = 0  # 1 Bit
        self.eof = 0  # 7 Bits
        
        self._msg_length_in_bit = 65  # no extension = 47, with extension = 65
        self.no_stuffing_bits = 0
        self.timestamp = timestamp

        # CAUTION: The length of the data field of the message is still 
        #          8 Bytes! The only difference is that there are 64 Bytes
        #          in that 8 Bytes
        
        self.unique_id = uuid.uuid4()
        
    @property
    
    def msg_length_in_bit(self):  # as seen from Bus System, so data field is max. 8 Bytes (but transports 64)
        ''' CAUTION THIS IS NOT THE NUMBER OF SEND BITS
            BUT THE LENGTH OF THE MESSAGE IF IT WAS A CAN FRAME
            
            SO USE A SIMPLE CAN TO TRANSPORT IT
    
            this is the length that is used by the CAN Bus
            to determine the size of the packet
            
            Input:   -
            Output:  size     integer    Size of this message segment in Bit        
        '''
        if self.seg_type == 0:  # single frame
            try:
                bit_rep = self.data.padded_size  # idea: if I send 32 bytes in CAN FD -> same as 4 bytes in CAN -> same as 4*8 = 32 bits
            except:
                bit_rep = len(self.data)
                
        if self.seg_type == 1:  # then this is a first frame 
            bit_rep = 62 + 2  # those 2 are control fields!

        if self.seg_type == 2:  # then this is a consecutive frame 
            try:
                bit_rep = self.data.padded_size  # 1 byte is a control field, Index
            except:
                bit_rep = len(self.data)
                
        self._msg_length_in_bit = 71 + bit_rep + self.no_stuffing_bits
        return self._msg_length_in_bit
        
        
