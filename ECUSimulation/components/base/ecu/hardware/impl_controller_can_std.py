
import simpy
from components.base.ecu.hardware.abst_controller import AbstractController
from tools.ecu_logging import ECULogger
from tools.general import General

class StdCanController(AbstractController):
    ''' 
    This Class implements a CAN Controller 
    '''
    
    def __init__(self, sim_env, rec_buffer_size=200000000, transmit_buffer_size=200000000):
        ''' Constructor
            
            Input:    sim_env                    simpy.Environment         environment of this component
                      rec_buffer_size            integer                   maximum capacity of the receiving buffer 
                      transmit_buffer_size       integer                   maximum capacity of the transmit buffer
            Output:   -
        '''
        AbstractController.__init__(self, sim_env)
        
        # buffer sizes
        self.max_receive_size = rec_buffer_size
        self.max_transmit_size = transmit_buffer_size
        
        # buffer stores
        self.transmit_buffer = LogStore(self.sim_env, capacity=200000000, max_size=transmit_buffer_size)
        self.receive_buffer = LogStore(self.sim_env, capacity=200000000, max_size=rec_buffer_size)
                
        
                
class LogStore(simpy.Store):
    '''
    this class is used to wrap the element of the buffer to be
    able to determine its size in bytes
    '''
    
    def __init__(self, env, capacity, max_size):
        ''' Constructor
        
            Input:    env         simpy.Environment          environment of this component
                      capacity    integer                    maxmium size of this buffer in elements
                      max_size    integer                    maximum size of this buffer in bytes
        '''
        super().__init__(env, capacity=capacity)                

        self.max_size = max_size
        self._elems = []  
        self.cur_elem_nr = 0      
        
        self.diabled_buffer_control = General().diabled_buffer_control
    
    def get_bytes(self):
        ''' returns the sum of the sizes of all elements in
            this buffer
            
            Input:     -
            Output:    size     float        size of all elements inside the buffer
        '''
        if self.diabled_buffer_control: return 0

        try:
            a = sum([(float(it.msg_length_in_bit) / 8.0) for it in self.items])
            
        except:
            a = 0
            ECULogger().log_traceback()
            print(self.items)
        return a
        
    
