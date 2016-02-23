import logging
import simpy

from components.base.ecu.software.abst_application_layer import AbstractApplicationLayer
from components.base.message.abst_bus_message import SegData
from testcases.utilities.archSaver import SaveRandom as SR
from components.security.ecu.software.impl_comm_module_secure import SecureCommModule



class TestApplicationLayer(AbstractApplicationLayer):
    ''' This class implements an Application 
        running on a specific ECU'''
#     START = 0.5

    

    def __init__(self, sim_env, ecu_id=-1):
        AbstractApplicationLayer.__init__(self, sim_env, ecu_id)

        self.sync = simpy.Store(self.sim_env, capacity=1)
        self.messages = None
        self.sendingProcesses = []
        self.start_times = []  # avoid two streams starting at the exact same time (not realistic and causes wrong behavior)
        
    def setMessages(self, messages):
        print("setting messages")
        for process in self.sendingProcesses:
            process.interrupt()
            
        self.messages = messages
        for msg_id in self.messages:
            print("starting sending process for msg ID " + str(msg_id))
            self.sendingProcesses.append(self.sim_env.process(self._main_send(msg_id)))
        
    def setRandomStartTime(self, on):
        self.randomStartTime = on
    
    def _main_receive(self):
        # skip the timeout add it later 
        self.comm_mod.skip_decryption_to = True
        while True:
            
            [self.msg_id, self.msg_data] = yield self.sim_env.process(self.comm_mod.receive_msg())
            now = self.sim_env.now + self.comm_mod.last_decryption_to
            if self.msg_id: pass  # logging.info("\n\tTime: %s \nECU_ID %s: Received a message %s" % (now, self._ecu_id, [self.msg_id, self.msg_data]))

    def _main_send(self, msg_id):
        '''random start time'''
        if(not self.randomStartTime):
            start_time = SR().ran.randint(0, 500) / 1000
            while start_time in self.start_times:
                start_time = SR().ran.randint(0, 500) / 1000
            self.start_times.append(start_time)
            yield self.sim_env.timeout(start_time)
        
        # always start same
#         TestApplicationLayer.START += 0.01
#         yield self.sim_env.timeout(TestApplicationLayer.START)
        
        
        
        
        while False == self.comm_mod.authenticator.confirmed:
            yield self.sim_env.timeout(1)
        
#         data = "x" * self.messages[msg_id].size
#         msg_data = SegData(data, self.messages[msg_id].size)
#         logging.info("\n\tTime: %s\nECU_ID %s: Sending msg_id: %s and data:  %s (interval: %s)" % (self.sim_env.now, self._ecu_id, msg_id, msg_data.get(), self.messages[msg_id]))
#         self.sim_env.process(self.comm_mod.send_msg(self._ecu_id, msg_id, msg_data.get()))
#         logging.info("\n\tTime: %s\nTask for ID %d, sleeping for %d", self.sim_env.now, msg_id, self.messages[msg_id].interval)
#         yield self.sim_env.timeout(self.messages[msg_id].interval)
#         logging.info("\n\tTime: %s\nTask for ID %d, waking up", self.sim_env.now, msg_id)
# 
#         while msg_id in list(self.comm_mod.authorizer.session_keys.keys()):
#             yield self.sim_env.timeout(1)
        print("sending process for msg ID " + str(msg_id) + " is running (time: " + str(self.sim_env.now) + ")")
        counter = 5
 
        data = "x" * self.messages[msg_id].size
        msg_data = SegData(data, self.messages[msg_id].size)
         
        # wait for grant then continue, if False deny message received
        if isinstance(self.comm_mod, SecureCommModule):
            granted = yield self.sim_env.process(self.comm_mod.request_grant(self._ecu_id, msg_id, msg_data.get()))  # sending normally done after encryption
            if not granted: return            

        while counter > 0:
            # stream granted send
            data = "x" * self.messages[msg_id].size
            msg_data = SegData(data, self.messages[msg_id].size)  
            # logging.info("\n\tTime: %s\nECU_ID %s: Sending msg_id: %s and data:  %s (interval: %s)" % (self.sim_env.now, self._ecu_id, msg_id, msg_data.get(), self.messages[msg_id]))             
            # logging.info("\n\tTime: %s\nTask for ID %d, sleeping for %d", self.sim_env.now, msg_id, self.messages[msg_id].interval)
             
            if isinstance(self.comm_mod, SecureCommModule):                
                yield self.sim_env.timeout(self.messages[msg_id].interval)
                self.sim_env.process(self.comm_mod.send_msg(self._ecu_id, msg_id, msg_data.get(), skip_timeout=True))  #  no timeout 
                self.comm_mod.request_timeout(self._ecu_id, msg_id, msg_data.get(), passed_encryption_time=True)  # log encryption time but now is now - encryption_time                
            else: 
                self.sim_env.process(self.comm_mod.send_msg(self._ecu_id, msg_id, msg_data.get()))
                 
                yield self.sim_env.timeout(self.messages[msg_id].interval)
            # logging.info("\n\tTime: %s\nTask for ID %d, waking up", self.sim_env.now, msg_id)
             
            if msg_id in list(self.comm_mod.authorizer.session_keys.keys()):
                counter = counter - 1

    def main(self):
        ''' main entrance point of the application        
        simply sends and receives Messages
        '''
        self.sim_env.process(self._main_receive())

        yield self.sim_env.timeout(0)




