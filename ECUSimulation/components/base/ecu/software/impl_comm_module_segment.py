from components.base.ecu.software.abst_comm_layers import AbstractCommModule
from components.base.ecu.software.impl_physical_layers import StdPhysicalLayer
from components.base.ecu.software.impl_datalink_layers import StdDatalinkLayer
from components.base.ecu.software.impl_transport_layers import SegmentTransportLayer
import config.timing_registration as time
from tools.general import General as G

class SegmentCommModule(AbstractCommModule):
    ''' This class implements a communication
        module, that simply forwards the messages to
        the next layer
    '''
    
    def __init__(self, sim_env, MessageClass):
        ''' Constructor
            
            Input:    sim_env              simpy.Environment                environment of this component
                      MessageClass         AbstractBusMessage            class that is used for sending and receiving
            Output:   -
        '''
        AbstractCommModule.__init__(self, sim_env, MessageClass)       
         
        # layers
        self.physical_lay = StdPhysicalLayer(sim_env) 
        self.datalink_lay = StdDatalinkLayer(sim_env) 
        self.transp_lay = SegmentTransportLayer(sim_env, MessageClass)      
        
        # connection between layers
        self.datalink_lay.physical_lay = self.physical_lay
        self.transp_lay.datalink_lay = self.datalink_lay        
        self.set_settings()
        
        # Timing Parameter 
        self.SCM_RECEIVE_PROCESS = time.SCM_RECEIVE_PROCESS
        self.SCM_SEND_PROCESS = time.SCM_SEND_PROCESS

    
    def set_settings(self):        
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        self.settings['t_send_process'] = 'SCM_SEND_PROCESS'
        self.settings['t_receive_process'] = 'SCM_RECEIVE_PROCESS'

    
    def receive_msg(self):
        ''' simply receives the messages from the transport layer, adds
            a delay to it and then pushes it to the application layer
            
            Input:        -
            Output:    message_data         object         Message that was sent on communication layer of sender side
                       message_id           integer        message identifier of the received message
            
        '''
        yield self.sim_env.process(G().to(self.sim_env, self.SCM_RECEIVE_PROCESS, 'SCM_RECEIVE_PROCESS', self.__class__.__name__))        
        [msg_id, msg_data] = yield self.sim_env.process(self.transp_lay.receive_msg())                
        return [msg_id, msg_data]
    
    
    def send_msg(self, sender_id, message_id, message):
        ''' send the message that was passed by further pushing it
            to the next layer and adding a delay
            
            Input:      sender_id      string        id of the sending component
                        message_id     integer        message identifier of the message that will be sent
                        message        object        Message that will be send on to the datalink layer
            Output:        -
        '''
        G().to_t(self.sim_env, self.SCM_SEND_PROCESS, 'SCM_SEND_PROCESS', self.__class__.__name__)         
        yield self.sim_env.timeout(self.SCM_SEND_PROCESS)
        yield self.sim_env.process(self.transp_lay.send_msg(sender_id, message_id, message))
        
        
