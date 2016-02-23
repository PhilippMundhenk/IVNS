from components.base.ecu.software.abst_comm_layers import AbstractCommModule
from components.base.ecu.software.impl_transport_layers import  FakeSegmentTransportLayer
from components.base.ecu.software.impl_datalink_layers import StdDatalinkLayer, \
    RapidDatalinkLayer
from components.base.ecu.software.impl_physical_layers import StdPhysicalLayer
from config import project_registration as proj
from config.specification_set import GeneralSpecPreset

class SecModStdCommModule(AbstractCommModule):
    ''' simple communication module in this case used for the 
        application with a security module'''

    def __init__(self, sim_env):
        ''' Constructor
            
            Input:  sim_env        simpy.Environment        environment of this component
            Output: -
        '''
        AbstractCommModule.__init__(self, sim_env)       
         
        # initialize layers
        self.transp_lay = FakeSegmentTransportLayer(sim_env, proj.BUS_MSG_CLASS)  
        self.datalink_lay = StdDatalinkLayer(sim_env)  
        self.physical_lay = StdPhysicalLayer(sim_env) 
        
        # preset used
        if GeneralSpecPreset().enabled: 
            self.transp_lay = GeneralSpecPreset().transport_layer(sim_env, proj.BUS_MSG_CLASS)  
            self.datalink_lay = GeneralSpecPreset().datalink_layer(sim_env)  
            self.physical_lay = GeneralSpecPreset().physical_layer(sim_env) 
                  
        # connect layers
        self.datalink_lay.physical_lay = self.physical_lay
        self.transp_lay.datalink_lay = self.datalink_lay

    
    def send_msg(self, sender_id, message_id, message):
        ''' send the message that was passed by further pushing it
            to the next layer
            
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
            Output: -
            Output:    -
        '''
        yield self.sim_env.process(self.transp_lay.send_msg(sender_id, message_id, message))
