import simpy
from components.security.ecu.software.impl_app_layer_regular import RegularApplicationLayer
from components.base.message.abst_bus_message import SegData

class BatManApplicationLayer(RegularApplicationLayer):
    ''' This class implements the application layer of the 
        battery manager. It's sending and receiving processes
        are tracked here
    '''
    
    def __init__(self, sim_env, ecu_id=-1):
        ''' Constructor
            
            Input:  sim_env        simpy.Environment        environment of this component
                    ecu_id         string                   id of the corresponding AbstractECU
            Output: -
        '''
        RegularApplicationLayer.__init__(self, sim_env, ecu_id)        
        self.sync = simpy.Store(self.sim_env, capacity=1)   
        
        self._bat_man_adapter = None 
        self._send_method = None
        
        
    def set_bat_man_adapter(self, adapter):
        ''' this method connects a BatManCANBusAdapter to this 
            ECU's application layer thus enabling to communicate with the 
            connected CMU that instantiates this adapter
            
            Input:     adapter        BatManCANBusAdapter    adapter connected to the CMU in the battery management environment
            Output:    -        
        '''
        # set the adapter
        self._bat_man_adapter = adapter
        
        # override the sending and the receiving function
        self._bat_man_adapter.CANsend = self._can_send
    
    def _can_send(self, message):
        ''' overrides the CAN send message method used in the CMU of the
            battery management system
        
            Input:    message    list        message of the battery management environment
            Output:    -
        '''
        # extract information
        message_id = message.identifier[0]
        message_size = message.identifier[1]
        
        # wrap it to message
        data = SegData(message, message_size)
        
        # start sending process
        self.sim_env.process(self.comm_mod.send_msg(self._ecu_id, message_id, data))
        
        if False: yield self.sim_env.timeout(0)

    
    def _main_receive(self):
        ''' infinitely waits for an incoming message and logs it once it arrives
            
            Input:    -
            Output:   -
        '''
        
        while True:
            
            # receive
            result = yield self.sim_env.process(self.comm_mod.receive_msg())
            
            # extract data
            [self.msg_id, self.msg_data] = [result[0], result[1]]
            
            # push to battery management
            if self.msg_data != None:
                self._bat_man_adapter.receive(self.msg_data.get())
