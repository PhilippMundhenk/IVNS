
import simpy
from components.base.bus.abst_bus_can import AbstractCANBus
import config.timing_registration as time
from tools.general import General as G, RefList, General
from config import project_registration as proj, can_registration
from tools.ecu_logging import ECULogger as L, ECULogger
from io_processing.surveillance_handler import MonitorInput, MonitorTags
import uuid
from uuid import UUID

class StdCANBus(AbstractCANBus):
    '''
    This class implements a CAN Bus on an
    abstracted level 
    '''
    
    def __init__(self, sim_env, bus_id, data_rate, avg_ecu_dist=2):
        ''' Constructor
            
            Input:    sim_env        simpy.Environment         environment in which this Bus acts
                      bus_id         string                    id of this Bus object
                      data_rate      float                     datarate of this bus
                      avg_ecu_dist   float                     average distance between two connected ECUs
                
            Output:   -                  
        '''
        AbstractCANBus.__init__(self, sim_env, bus_id, data_rate, avg_ecu_dist)
        
        # bus objects
        self.current_message = None  # current message on the bus [sender_ecu, message]
        self.set_settings()
        self.monitor_list = RefList()
        self._used_prop_times = {}
        self.gateways = []
        self.first = True
        
        # synchronization objects
        self.pot_messages = []  # gathers all potential messages that want to be sent at a certain point in time
        self.sync_1 = simpy.Store(self.sim_env, capacity=1)  # if the decision, who is allowed to sent is done this synchronizer starts the transmission
        self.sync_2 = simpy.Store(self.sim_env, capacity=1)  # if store is empty then the channel is busy
        self.sync_send = simpy.Store(self.sim_env, capacity=1)  # store that is full if sending and free else
        self.subscribers = 0  # number of ECUs waiting for the channel to be freed
            
        # project parameters
        self.SCB_GATHER_MSGS = time.SCB_GATHER_MSGS
        self.SCB_GRAB_PRIO_MSG = time.SCB_GRAB_PRIO_MSG
        self.SCB_PROPAGATION_DELAY = time.SCB_PROPAGATION_DELAY
        self.SCB_SENDING_TIME = time.SCB_SENDING_TIME
        self.SCB_WRITE_TO_TRANSCEIVER_BUFFER = time.SCB_WRITE_TO_TRANSCEIVER_BUFFER

    def monitor_update(self):
        ''' returns the input for the monitor 
        
            Input:    -
            Output:   monitor_list    list    List of MonitorInput objects
        '''
        self.monitor_list.clear_on_access()  # on the next access the list will be cleared        
        return self.monitor_list.get()

    
    def put_message(self, message):
        ''' if more than one message is to be sent within a period (assumed at the same time), the one 
            with lower message_id wins and the other one must be informed to retry
            
            Input:     message     AbstractBusMessage    current message to be put on the bus
            Output:    bool        boolean               true for the ECU that was able to put the message on the bus. False for all others
        '''
        
        # gather potential senders
        if self._gather_messages(message): 
            yield self.sim_env.timeout(self.SCB_GATHER_MSGS)
        
        # send highest priority
        if self._grab_highest_priority(): 
            yield self.sim_env.timeout(self.SCB_GRAB_PRIO_MSG)
        
        # set current message
        self.current_message = self._get_highest_priority_msg(self.pot_messages)
        self.current_message_length_bit = self.current_message.msg_length_in_bit
        
        # start transmission
        self.sync_1.put(True)
        
        #  return if sender's message sent
        if message == self.current_message: return True
        else: return False
        
    
    def process(self):
        ''' Does the actual transmission of data: So gathers the message that was put on
            the bus and writes it to the receiving buffer of all connected ECUs
            
            Input:   -
            Output:  -            
        '''
        
        while True:           
            
            # wait for message
            yield self.sync_1.get() 
            
            # transmit message
            if self.current_message != None:
                
                # monitor start
                monitor_note = self._monitor_transmission_start()
                
                # write to buffer
                yield self.sim_env.process(self._wait_transmission_time_and_buffer())
                self._reset_transmission()

                # monitor end
                self._monitor_transmission_end(monitor_note)
             
    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        # parameter
        self.settings['t_gather_msg'] = 'SCB_GATHER_MSGS'
        self.settings['t_grab_prio_msg'] = 'SCB_GRAB_PRIO_MSG'
        self.settings['t_propagation_delay'] = 'SCB_PROPAGATION_DELAY'
        self.settings['t_sending_time'] = 'SCB_SENDING_TIME'
        self.settings['t_write_to_transceiver_buffer'] = 'SCB_WRITE_TO_TRANSCEIVER_BUFFER' 
              
    
    def wait_until_free(self):
        ''' when the channel is busy some ECUs can start this method in
            a simpy process. Once the channel is free this process ends 
            and the next ECU can start it's transmission             
            technically:
            count number of waiting processes and notifies them all once the channel is free
            
            Input:    -
            Output    -
        '''
        # add subscriber
        self.subscribers += 1                
        yield self.sync_2.get()
        
        # release all receivers
        while self.subscribers > 1:           
            
            self.sync_2.put(True)
            self.subscribers -= 1 
        self.subscribers = 0           
     
    
    def _extract_transmission_times(self):
        ''' calculates the time the current transmission takes
            
            Input:       -
            Output: t_propagation:    float    time it takes to propagate the message
                    t_sending         float    time it takes to send the message
        '''
        
        t_propagation = time.call(self.SCB_PROPAGATION_DELAY, self.avg_dist_between_ecus)  # either constant or calculated depending on config
        t_sending = time.call(self.SCB_SENDING_TIME, self.current_message_length_bit, proj.BUS_ECU_DATARATE)  # either constant or calculated depending on config
        
        return t_propagation, t_sending

    
    def _gateway_sends(self, ecu):
        ''' if gateway is the sender let it continue 
            and reset the message state
            
            Input:  ecu     AbstractECU    current ECU that sends the message            
            Output: bool    boolean        True if the message was sent by this ECU
        '''
        try:
            if ecu.ecu_id in self.current_message.gw_id:  # send message back and forth send could lead to errors: need to reset gw_id list
                return True
        except:
            return False
        
        return False
     
     
    def _gather_messages(self, message):
        ''' gather all messages that can potentially be
            sent
            
            Input:   message    object    the message that will potentially be send
            Output:  -
        '''
        # add potential message
        self.pot_messages.append(message)

        # timeout if not zero
        if self.SCB_GATHER_MSGS != 0:
            G().to_t(self.sim_env, self.SCB_GATHER_MSGS, 'SCB_GATHER_MSGS', self.__class__.__name__, message.sender_id)
            return True
        return False
    
    
    def _get_highest_priority_msg(self, message_list):
        ''' returns the message with the highest priority
            
            Input:     message_list    list        list of messages
            Output:    message         object      message with highest priority (lowest message id)
        '''
        min_val = float("inf")
        message = None
        for cur_message in message_list:            
            if min_val > cur_message.message_identifier:
                min_val = cur_message.message_identifier
                message = cur_message
        return message
    
    
    def _grab_highest_priority(self):
        ''' note the time it takes to select the message with
            the highest priority
        
            Input:     -
            Output:    -            
        '''
        if self.SCB_GRAB_PRIO_MSG != 0:
            G().to_t(self.sim_env, self.SCB_GRAB_PRIO_MSG, 'SCB_GRAB_PRIO_MSG', self.__class__.__name__, self) 
            return True
        return False
    
    
    def _monitor_transmission_start(self):
        ''' notes the start time when this message was put on the bus
            
            Input:  -
            Output: -
        '''
        
        # extract information 
        uid = uuid.uuid4()
        tag = MonitorTags.CB_PROCESSING_MESSAGE
        c_id = self.comp_id
        sender_id = self.current_message.sender_id
        msg_id = self.current_message.message_identifier
        msg_uid = self.current_message.data.unique_id
        data = self.current_message.data.get();         
        
        # extract further information         
        msg = self.current_message
        size = self.current_message_length_bit / 8
        self.current_message.data.unique_id = msg_uid
        
        # send to monitor
        G().mon(self.monitor_list, MonitorInput(data, tag, c_id, self.sim_env.now, sender_id, msg_id, msg, size, msg_id, uid.hex))        
        return data, c_id, sender_id, msg_id, msg, size, uid
           
    
    def _monitor_transmission_end(self, mon_out):
        ''' notes the end time when this message was put on the bus
            
            Input:  -
            Output: -
        '''
        G().mon(self.monitor_list, MonitorInput(mon_out[0], MonitorTags.CB_DONE_PROCESSING_MESSAGE, \
                                                mon_out[1], self.sim_env.now, mon_out[2], mon_out[3], \
                                                mon_out[4], mon_out[5], -1, mon_out[6].hex))

    
    def _push_to_receivers(self):
        ''' writes the current message to all ecus that 
            are connected to this Bus
        
            Input:       -
            Output:      -
        '''
        # get gateways
        if self.first:
            self.gateways = [itm.ecu_id for itm in self.connected_ecus if isinstance(itm.ecu_id, UUID)]
            self.first = False
        
        # send only to receivers
        if General().send_only_to_receivers and self.current_message.message_identifier not in can_registration.AUTH_MESSAGES:     
            
            run_list = General().sender_receiver_map[self.current_message.sender_id][self.current_message.message_identifier] + self.gateways
                   
            for ecu in self.connected_ecus:

                # send only to allowed receivers
                if ecu.ecu_id not in run_list:
                    continue
                
                # Gateway:avoid sending to itself (loops)
                if self._gateway_sends(ecu): continue
    
                # ECU: avoid sending to itself
                if(ecu.ecu_id != self.current_message.sender_id):
                    self.current_message.current_bus = self.comp_id
    
                    ecu.ecuHW.transceiver.get(self.current_message)
        
        else:
            # iterate over receivers      
            for ecu in self.connected_ecus:
                
                # Gateway:avoid sending to itself (loops)
                if self._gateway_sends(ecu): continue
    
                # ECU: avoid sending to itself
                if(ecu.ecu_id != self.current_message.sender_id):
                    self.current_message.current_bus = self.comp_id
    
                    ecu.ecuHW.transceiver.get(self.current_message)

    
    def _reset_transmission(self):
        ''' after one message was sent three things have to be reset
            the current message. The synchronizer for the selection
            of the next higher prioritized message to be sent and the 
            list that gathered the selected potential messages
            
            Input:     -
            Output:    -
        '''
        self.current_message = None  # message is not on the line anymore
        self.sync_2.put(True)  # channel is free again
        self.pot_messages = []  # reset

    
    def _sending_ok(self, t_propagation, t_sending):
        ''' checks if this message is sendable
            
            Input:  t_propagation:    float    time it takes to propagate the message
                    t_sending         float    time it takes to send the message
            Output: bool              boolean  true if the time is valid
        '''
        try:
            G().to_t(self.sim_env, t_propagation + t_sending + self.SCB_WRITE_TO_TRANSCEIVER_BUFFER, 'SCB_PROPAGATION_DELAY+SCB_SENDING_TIME+SCB_WRITE_TO_TRANSCEIVER_BUFFER', self.__class__.__name__, self)
            if t_propagation + t_sending + self.SCB_WRITE_TO_TRANSCEIVER_BUFFER > 0:
                return True        
            # logging.error("Error (skipped with time 0):t_propagation =%s, t_sending = %s, self.SCB_WRITE_TO_TRANSCEIVER_BUFFER = %s // msg_length_bit = %s" % \
            #              (t_propagation, t_sending, self.SCB_WRITE_TO_TRANSCEIVER_BUFFER, self.current_message_length_bit))
        except: 
            return False
        return False
    
    
    def _try_logging_transmission(self, t_propagation, t_sending):
        ''' notes the times that it takes to send the messages
        
            Input:  t_propagation:    float    time it takes to propagate the message
                    t_sending         float    time it takes to send the message
        '''
                        
        try:
            # Log transmission
            L().log(300, self.sim_env.now, self.current_message.sender_id, float(self.current_message_length_bit) / 8.0, \
                    self.current_message_length_bit, self.comp_id, self.current_message.data.get(), t_propagation + t_sending) 
        except:
            
            # Log traceback
            ECULogger().log_traceback()
            try: 
                L().log(300, self.sim_env.now, self.current_message.sender_id, self.current_message.data, \
                        self.current_message_length_bit, self.comp_id, self.current_message.data, t_propagation + t_sending)
            except: pass
    
    
    def _wait_transmission_time_and_buffer(self):
        ''' this method times out for the duration of the transmission and
            then writes the sent messages to the receiving buffer of the ecu
            
            Input:       -
            Output:      -
        '''
        
        if not self.current_message_length_bit in self._used_prop_times:
            # sending times         
            t_propagation, t_sending = self._extract_transmission_times()    
            
            # duration of transmission    
            wait_time = t_propagation + t_sending + self.SCB_WRITE_TO_TRANSCEIVER_BUFFER 
            if wait_time <= 0: wait_time = 0.000001
            self._used_prop_times[self.current_message_length_bit] = wait_time      
            
        else:
            wait_time = self._used_prop_times[self.current_message_length_bit]
            
        yield self.sim_env.timeout(wait_time)
        
        # put to connected ecus
        self._push_to_receivers()
        
        # sync done
        self.sync_send.put(True)
        
