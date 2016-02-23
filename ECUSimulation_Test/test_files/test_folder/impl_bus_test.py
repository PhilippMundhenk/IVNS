
from components.base.bus.abst_bus_can import AbstractCANBus


class TestBus(AbstractCANBus):
    '''
    This class implements a CAN Bus on an
    abstracted level 
    '''
    
    def __init__(self, sim_env, bus_id, data_rate, avg_ecu_dist=2):
        AbstractCANBus.__init__(self, sim_env, bus_id, data_rate, avg_ecu_dist)
        
        ''' bus objects '''
        self.current_message = None  # current message on the bus [sender_ecu, message]

