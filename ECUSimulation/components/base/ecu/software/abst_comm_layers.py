from components.base.automotive_component import AutomotiveComponent
from config import project_registration as proj
import uuid
from PyQt4.Qt import QObject
from PyQt4 import QtCore

class AbstractCommModule(QObject):
    ''' 
    This abstract class defines the interface of
    a Communication Module, that is responsible for 
    sending and receiving messages (securely)
    '''
    changed_sym_key = QtCore.pyqtSignal(list)
    
    def __init__(self, sim_env, phys_lay=None, data_lay=None, transport_lay=None):
        ''' Constructor
            
            Input:    sim_env          simpy.Environment                environment of this component
                      phys_lay         AbstractPhysicalLayer            physical Layer of this module
                      data_lay         AbstractDataLinkLayer            data link Layer of this module
                      transport_lay    AbstractTransportLayer           transport Layer of this module
            Output:   -
        '''
        QObject.__init__(self)        
        
        # component information
        self.sim_env = sim_env
        self.comp_id = uuid.uuid4()        
        self._jitter = 1
        
        # layers
        self.transp_lay = transport_lay
        self.physical_lay = phys_lay
        self.datalink_lay = data_lay
        
        # project parameter
        self.MessageClass = proj.BUS_MSG_CLASS
    
    
    def send_msg(self, message):
        ''' send the message that was passed by further pushing it
            to the next layer
            
            Input:     message        object        Message that will be send on to the transport layer
            Output:    -
        '''
        
    
    def receive_msg(self):
        ''' receives a message from the next lower layer
            (transport layer) and then the returned value is
            pushed to the application layer
            
            Input:     -
            Output:    message_data         object         Message that was sent on communication layer of sender side
                       message_id           integer        message identifier of the received message
        '''
        [message_id, message_data] = yield self.sim_env.process(self.transp_lay.receive_msg())        
        
        return [message_id, message_data]
    
class AbstractTransportLayer(AutomotiveComponent):
    ''' 
    This abstract class defines the interface of
    a transport layer being invoked by the application
    layer
    '''

    def __init__(self, sim_env, test=None):
        ''' Constructor
            
            Input:    sim_env          simpy.Environment                environment of this component                      
            Output:   -
        '''
        AutomotiveComponent.__init__(self, sim_env)
        
        self.datalink_lay = None    
        self.MessageClass = proj.BUS_MSG_CLASS          
        self._jitter = 1  
        
    
    def send_msg(self, sender_id, message_id, message):
        ''' send the message that was passed by further pushing it
            to the next layer
            
            Input:  sender_id      string        id of the sending component
                    message_id     integer       id of the message to be sent
                    message        object        Message that will be send on to the datalink layer
            Output:    -
        '''
    
    
    def receive_msg(self):
        ''' receives a message from the next lower layer
            (datalink layer) and then the returned value is
            pushed to the communication module
            
            Input:     -
            Output:    message_data         object         Message that was sent on communication layer of sender side
                       message_id           integer        message identifier of the received message
        '''
        return [None, None]

class AbstractDataLinkLayer(AutomotiveComponent):
    ''' 
    This abstract class defines the interface of
    a DataLink Layer that belongs to a Communication 
    Module
    '''
    
    def __init__(self, sim_env):
        ''' Constructor
            
            Input:    sim_env          simpy.Environment                environment of this component                      
            Output:   -
        '''
        AutomotiveComponent.__init__(self, sim_env)
        self.physical_lay = None       
        self.controller = None
        self._jitter = 1
        self.effective_bittime = 0 
        
    
    def process(self):
        ''' this process puts and pulls messages from the
        buffer onto the bus via the physical layer
        
        Input:     -
        Output:    -
        '''
        
    
    def pull_msg(self):
        ''' pulls the message from the transceiver and returns it 
            back to a higher level 
            
            Input:     -
            Output:    -
        '''    
        return None
    
    
    def put_msg(self, msg):
        ''' gives a message to the transceiver once it 
            is allowed to do so
        
            Input:     -
            Output:    -
        '''
        
class AbstractPhysicalLayer(AutomotiveComponent):
    ''' 
    This abstract class defines the interface of
    a Physical Layer that belongs to a Communication 
    Module
    '''
 
    def __init__(self, sim_env):
        ''' Constructor
            
            Input:    sim_env          simpy.Environment                environment of this component                      
            Output:   -
        '''
        AutomotiveComponent.__init__(self, sim_env)
        self.datalink_lay = None
        self.transceiver = None
        self._jitter = 1
        
    
    def put(self, message):
        ''' gives a message to the transceiver who
        puts it on the bus
        
        Input:     message    Object    message to be pushed on the bus
        Output:    -
        '''
        
    
    def bus_free(self):
        ''' true if the connected Bus is free 
        
        Input:     -
        Output:    bool    boolean    true if the connected bus is free
        '''
        
    
    def wake_if_channel_free(self):
        ''' stuck until bus is free again 
        
            Input:     -
            Output:     -
        '''

        
        
