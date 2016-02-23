
import pyqtgraph.examples 
import sys

pyqtgraph.examples.run()
sys.exit(0)
class D(object):

    def __init__(self):
        self.padded_size = 0    
        self._size = None
    
    def __len__(self):
        return self._size

seg_type = 2
no_stuffing_bits = 2
data = D()



try:
    if seg_type == 0:  # single frame
        try:
            bit_rep = data.padded_size  # idea: if I send 32 bytes in CAN FD -> same as 4 bytes in CAN -> same as 4*8 = 32 bits
        except:
            bit_rep = len(data)
            
    if seg_type == 1:  # then this is a first frame 
        bit_rep = 62 + 2  # those 2 are control fields!

    if seg_type == 2:  # then this is a consecutive frame 
        try:
            bit_rep = data.padded_size  # 1 byte is a control field, Index
        except:
            bit_rep = len(data)
            
    _msg_length_in_bit = 71 + bit_rep + no_stuffing_bits

except:     
    bit_rep = ""        
    if seg_type == 0:  # single frame
        bit_rep = data.padded_size  # idea: if I send 32 bytes in CAN FD -> same as 4 bytes in CAN -> same as 4*8 = 32 bits
    
    if seg_type == 1:  # then this is a first frame 
        bit_rep = 62 + 2  # those 2 are control fields!
        
    if seg_type == 2:  # then this is a consecutive frame 
        bit_rep = data.padded_size  # 1 byte is a control field, Index
            
    _msg_length_in_bit = 71 + bit_rep + no_stuffing_bits


print(_msg_length_in_bit)
