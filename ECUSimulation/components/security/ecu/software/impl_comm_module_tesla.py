from components.base.ecu.software.abst_comm_layers import AbstractCommModule
from components.base.ecu.software.impl_physical_layers import StdPhysicalLayer
from components.base.ecu.software.impl_datalink_layers import StdDatalinkLayer
from components.base.ecu.software.impl_transport_layers import FakeSegmentTransportLayer
from tools.ecu_logging import try_ex, ECULogger
from tools.general import RefList, General as G
import simpy
from components.security.encryption.encryption_tools import MACKey, \
    asy_get_key_pair, asy_encrypt, asy_decrypt, mac, same_mac_ct
from enums.sec_cfg_enum import PRF, EnumTrafor    
from _md5 import md5
import math
from tools.singleton import Singleton
from _sha1 import sha1
import os
from config import can_registration
from components.base.message.abst_bus_message import SegData
from components.security.encryption.public_key_manager import PublicKeyManager
from math import floor
from uuid import uuid4
import config.project_registration as proj
import config.timing_registration as time
from io_processing.surveillance_handler import MonitorInput, MonitorTags
import uuid
from config.specification_set import GeneralSpecPreset
import numpy
import logging


class TeslaCommModule(AbstractCommModule):
    ''' This class implements a secure communication
        module, that enables secure communication between
        several ECUs via Tesla
    '''
    
    CREATED_KEYS = []  # to avoid longer run times use same keys for every stream and every ecu
    KX_EXPECTED_NUMBER = {}  # key: stream id value: expected number of key exchange messages
    KX_SETUP_NOTIFY_STORES = {}  # key: stream id value: simpy store, continueing at sender when all receivers decrypted there exchange key
    KX_ACTUAL_NUMBER = {}  # key: stream_id, value number of ecus that already received a key_exchange
    
    KX_TIME_SYNC_DONE_STORES = {}  # key: sender id value: simpy store, continue when time synchronization is done
    KX_EXPECTED_RECS = {}  # key: sender id value: list of expected receivers for timing sync with the sender in key
    KX_ACTUAL_RECS = {}  # key: sender, value: list of actual receivers for timing sync with the sender in key
   
    
    def __init__(self, sim_env, ecu_id):
        ''' Constructor
            
            Input:  ecu_id         string                   id of the corresponding AbstractECU
                    sim_env        simpy.Environment        environment of this component
            Output:  -
        '''
        AbstractCommModule.__init__(self, sim_env)

        # local parameters
        self._ecu_id = ecu_id
        self._jitter_in = 1        
        self._streams = []  # all streams of the simulation        
        self._messages_to_return = []  # buffered messages that are to be returned to higher layers
        self._directed_ecus = []  # ecus that have been already directed due to time synchronization
        self._current_received = None
        self._sync = simpy.Store(self.sim_env, capacity=1)    
        
        
        self.sender_streams = []  # list of streams where this ECU is the sender
        self.receiver_streams = []  # list of streams where this ECU is the receiver
        self.rec_stream_ids = []  # stream ids where this ecu is receiver
        self.send_stream_ids = []  # stream ids where this ecu is sender
        self.set_up = False  # indicates if all defined streams are set up        
        self.monitor_list = RefList()
        
        # message categories
        self._time_sync_ids = [can_registration.CAN_TESLA_TIME_SYNC, can_registration.CAN_TESLA_TIME_SYNC_RESPONSE]
        self._key_exchange_ids = [can_registration.CAN_TESLA_KEY_EXCHANGE]
        
        # initialize
        self._init_project_parameter()
        self._init_layers(self.sim_env, self.MessageClass)
        self._init_sublayers()
        
    def add_stream(self, new_stream):
        ''' adds a stream to the list of registered
            streams in the simulation
        
            Input:    new_stream    MessageStream    stream to be added
            Output:   -    
        '''
        self._streams.append(new_stream)
    
    
    def receive_msg(self):
        ''' receives messages via the tesla mechanism after
            they where authenticated. Then messages that were 
            authenticated are buffered in _messages_to_return
            and returned to higher layers sequentially on each 
            call of this method
            
            Input:     -
            Output:    message_data    object/string/...    message that was received
                       message_id      integer              id of received message
        '''
        
        # return buffered message if available
        if self._messages_to_return: return self._return_next_message()
            
        while True:
            
            # receive 
            [message_id, message_data] = yield self.sim_env.process(self.transp_lay.receive_msg())        

            # check destination
            if not self._correct_addressed(message_data): continue
            
            # reset
            received = False
            
            # time synchronization
            if message_id in self._time_sync_ids:
                yield  self.sim_env.process(self._time_sync.process(message_data.sender_id, message_id, message_data))
            
            # initial key exchange
            if message_id in self._key_exchange_ids:
                yield  self.sim_env.process(self._receiver.process(message_data.sender_id, message_id, message_data))
                
            # message received
            if message_id in self.rec_stream_ids:
                received = yield self.sim_env.process(self._receiver.process(message_data.sender_id, message_id, message_data))

            # return next buffered
            if received: return self._return_next_message(received, message_id)           
                
        # push to higher layer
        return [message_id, message_data]

    def send_msg(self, sender_id, message_id, message):
        ''' this  method checks if the setup phase was complete.
            Once it is the messages are sent to its destination
            
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
            Output: -
        
        '''
        # if allowed stream send        
        if self.set_up and message_id in self.send_stream_ids:
            self.sim_env.process(self._sender.transmit(message_id, message, self._get_receivers(message_id)))
        
        # dummy for simpy
        if False: yield  self.sim_env.timeout(0) 
    
    def run_setup_phase(self):
        ''' initializes the setup for the tesla process. First all receivers of 
            a stream will start a time synchronization message to all receivers
            of them. Then the sender ecu starts to generate a defined number of 
            MAC keys. After that the first of those keys is encrypted using 
            public encryption of the destination ecus and is then forwarded to all
            receivers
            
            Input:   -
            Output:  -
        '''
        yield self.sim_env.timeout(0.0000000001)
        
        # initialize lists
        sender_ids_to_sync = self._initialize_setup()
       
        # receiver: setup
        self._setup_receiver_streams()
       
        # receiver: start synchronization once per target
        self._time_sync.expected_sync_messages = len(sender_ids_to_sync) 
        if len(sender_ids_to_sync) == 0: self._time_sync.time_sync_done_sync.put(True)       
        for sender_id in sender_ids_to_sync:        
            if self._already_directed(sender_id): continue
            yield self.sim_env.process(self._time_sync.receiver_sync_init(sender_id))
        
        # wait until the sync process is done
        TeslaCommModule.KX_TIME_SYNC_DONE_STORES[self._ecu_id] = simpy.Store(self.sim_env, capacity=1)
        TeslaCommModule.KX_ACTUAL_RECS[self._ecu_id] = []
        TeslaCommModule.KX_EXPECTED_RECS[self._ecu_id] = self._receivers_from_stream(self.sender_streams)  # all receivers for this ecu
        
        if self.sender_streams:
            yield TeslaCommModule.KX_TIME_SYNC_DONE_STORES[self._ecu_id].get()
        
            # sender: initialize 
            yield self.sim_env.process(self._sender.run_setup(self.sender_streams))
            
        # exchange first key         
        for stream in self.sender_streams:
            yield self.sim_env.process(self._sender.exchange_first_key(stream))
            
        # indicate set up complete
        if not self.receiver_streams: self.set_up = True
    
    def notify_key_ex_complete(self, stream_id):
        ''' started in a simpy process this method will wait until all expected key
            exchange messages for this stream_id are received and will continue then
         
            Input:    stream_id    integer    stream id to wait for
            Output:   -
        '''
        if stream_id not in TeslaCommModule.KX_SETUP_NOTIFY_STORES:
            TeslaCommModule.KX_SETUP_NOTIFY_STORES[stream_id] = simpy.Store(self.sim_env, capacity=1)

        yield TeslaCommModule.KX_SETUP_NOTIFY_STORES[stream_id].get()
    
    def _receivers_from_stream(self, streams):
        ''' returns all ecu ids of the given receivers in the given streams
            
            Input:     streams    list    list of streams
            Output:    ecu_ids    list    list of receiver ecu ids 
        '''
        lst = []
        for stream in streams:
            for receiver in stream.receivers:
                if receiver not in lst:
                    lst.append(receiver)
        return lst
            
    def _already_directed(self, sender_id):
        ''' true if the incoming sender was already
            directed by this ecu during the synchronization
            process
            
            Input:    sender_id    string    id of the next sender to be directed
            Output:   bool         boolean   true if this sender was not directed yet 
        '''
        if sender_id in self._directed_ecus: 
            return True
        self._directed_ecus.append(sender_id)
        return False
    
    
    def _correct_addressed(self, message_data):
        ''' returns true if the message data (not yet 
            authenticated) was meant for this ecu and 
            this ecu should read it
            
            Input:    message_data    SegData    received message from the transport layer
            Output:   bool            boolean    true if message meant for this ecu else false
        '''
        try: 
            if self._ecu_id in message_data.dest_id: ok = True
            else: ok = False
        except: ok = False            
        if (not ok) and message_data.dest_id != self._ecu_id: 
            return False
        return True
    
       
    def _extract_where_sender_id(self, ecu_id, streams):
        ''' returns all streams where the sender is ecu_id
            
            Input:    ecu_id            string    ecu id considered
                      streams           list      list of all MessageStream objects for this simulation
            Output:   found_streams     list      list of MessageStream objects where this ecu is the sender  
        '''
        found_streams = []
        for stream in streams:
            if stream.sender_id == ecu_id and stream not in found_streams:
                found_streams.append(stream)
        return found_streams
        
    
    def _extract_where_receiver_id(self, ecu_id, streams):
        ''' return all streams where ecu_id is a receiver
        
            Input:    ecu_id            string    ecu id considered
                      streams           list      list of all MessageStream objects for this simulation
            Output:   found_streams     list      list of MessageStream objects where this ecu is a receiver  
        '''
        found_streams = []
        for stream in streams:
            if ecu_id in stream.receivers and stream not in found_streams:
                found_streams.append(stream)
        return found_streams
        
    
    def _initialize_setup(self):
        ''' initializes the setup phase of the tesla mechanism. Extracts
            the stream lists from all available streams of this simulation
            
            Input:    -
            Output:   sender_ids_to_sync    list    list of ids this receiver has to synchronize with
        '''
        # log
#         logging.info("%s - ECU %s: Start setup" % (self.sim_env.now, self._ecu_id))
        
        # sender streams
        self.sender_streams = self._extract_where_sender_id(self._ecu_id, self._streams)       
        self.send_stream_ids = [s.message_id for s in self.sender_streams]
        
        # receiver streams
        self.receiver_streams = self._extract_where_receiver_id(self._ecu_id, self._streams)
        self.rec_stream_ids = [s.message_id for s in self.receiver_streams]
        
        # ids to sync with
        sender_ids_to_sync = self._senders_to_sync()
        
        return sender_ids_to_sync
        
    
    def _senders_to_sync(self):
        ''' determine all senders that this ecu has to sync with. So all
            stream senders where this ecu is the receiver
            
            Input:    -
            Output:   synchronization_ids    list     list of sender ids with which this ecu will synchronize
        '''
        synchronization_ids = []
        for stream in self._streams:
            if self._ecu_id in stream.receivers and stream.sender_id not in synchronization_ids:
                synchronization_ids.append(stream.sender_id)
        return synchronization_ids

    
    def _get_receivers(self, stream_id):
        ''' returns all receivers for the stream with 
            message id stream_id 
            
            Input:    stream_id    integer    id of the stream
            Output:   receivers    list       list of receivers for the given stream 
        '''
        for stream in self._streams:
            if stream.message_id == stream_id and stream.sender_id == self._ecu_id:
                return stream.receivers
        return []
        
    
    def _init_project_parameter(self):
        ''' initializes all project parameters that can be configured
            
            Input:    -
            Output:   - 
        '''
        # number of generated keys
        self.TESLA_KEY_CHAIN_LEN = proj.TESLA_KEY_CHAIN_LEN
        
        # setup phase
        self.TESLA_MAC_KEY_ALGORITHM = proj.TESLA_MAC_KEY_ALGORITHM
        self.TESLA_MAC_KEY_LEN = proj.TESLA_MAC_KEY_LEN
                
        self.TESLA_PRF_KEY_CHAIN = proj.TESLA_PRF_KEY_CHAIN
        self.TESLA_PRF_MAC_KEY = proj.TESLA_PRF_MAC_KEY 
                
        # initial key exchange
        self.TESLA_KEY_EXCHANGE_ENC_ALGORITHM = proj.TESLA_KEY_EXCHANGE_ENC_ALGORITHM
        self.TESLA_KEY_EXCHANGE_KEY_LEN = proj.TESLA_KEY_EXCHANGE_KEY_LEN
        self.TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION = proj.TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION      
        self.TESLA_KEY_EXCHANGE_CLEAR_SIZE = proj.TESLA_KEY_EXCHANGE_CLEAR_SIZE
        self.TESLA_KEY_EXCHANGE_CIPHER_SIZE = proj.TESLA_KEY_EXCHANGE_CIPHER_SIZE
        
        # key legid check
        self.TESLA_KEY_LEGID_MAC_ALGORITHM = proj.TESLA_KEY_LEGID_MAC_ALGORITHM
        self.TESLA_KEY_LEGID_MAC_KEY_LEN = proj.TESLA_KEY_LEGID_MAC_KEY_LEN
        
        self.TESLA_MAC_SIZE_TRANSMIT = proj.TESLA_MAC_SIZE_TRANSMIT  # size of one MAC after encryption
        
        self.TESLA_ONE_KEY_CREATION = time.TESLA_ONE_KEY_CREATION  # time to generate one MAC
        self.TESLA_MAC_GEN_VERIFY_TIME_TRANSMIT = time.TESLA_MAC_GEN_VERIFY_TIME_TRANSMIT  # time to generate the mac to compare it with the generated at transmit
        self.TESLA_MAC_GEN_TIME_TRANSMIT = time.TESLA_MAC_GEN_TIME_TRANSMIT  # time to generate the mac from a input
        self.TESLA_KEY_EXCHANGE_ENC_TIME = time.TESLA_KEY_EXCHANGE_ENC_TIME  # time to encrypt the first message publically
        self.TESLA_KEY_EXCHANGE_DEC_TIME = time.TESLA_KEY_EXCHANGE_DEC_TIME  # time to decrypt the first message privately
        self.TESLA_KEY_LEGID_PRF_TIME = time.TESLA_KEY_LEGID_PRF_TIME  # time for one PRF run to legitimate the Key
        
    
    def _init_layers(self, sim_env, MessageClass):
        ''' Initializes the software layers 
            
            Input:  sim_env                        simpy.Environment        environment of this component                      
                    MessageClass                   AbstractBusMessage       class of the messages  how they are sent on the CAN Bus
            Output: -                   
        '''
        
        # create layers
        self.physical_lay = StdPhysicalLayer(sim_env)         
        self.datalink_lay = StdDatalinkLayer(sim_env) 
        self.transp_lay = FakeSegmentTransportLayer(sim_env, MessageClass)
   
        # preset used
        if GeneralSpecPreset().enabled:
            self.transp_lay = GeneralSpecPreset().transport_layer(sim_env, MessageClass)  
            self.datalink_lay = GeneralSpecPreset().datalink_layer(sim_env)  
            self.physical_lay = GeneralSpecPreset().physical_layer(sim_env) 
   
        # interconnect layers             
        self.datalink_lay.physical_lay = self.physical_lay        
        self.transp_lay.datalink_lay = self.datalink_lay           
        
    
    def _init_sublayers(self):
        ''' initializes the sublayers which are the sending activities
            of the ecu, it's receiving activities and the time synchronization
        
            Input:    -
            Output:   - 
        '''
        self._sender = TeslaSender(self.sim_env, self.transp_lay, self._ecu_id, self, self.monitor_list, self._jitter_in)
        self._receiver = TeslaReceiver(self.sim_env, self.transp_lay, self._ecu_id, self, self.monitor_list, self._jitter_in)
        self._time_sync = TeslaSynchronizeTime(self.sim_env, self.transp_lay, self._ecu_id, self._sender, self._receiver, self.monitor_list, self._jitter_in)
     
            
    def _return_next_message(self, entry=False, message_id=False):
        ''' this method returns the next validated
            message. If entry is given also a new
            message will be put in the buffer
            
            Input:    entry           object     if given this value will be added to the list
            Output:   return_value    object     message that was authenticated list of [msg_id, msg_data] lists
        '''
        # add entry
        if entry:
            rec = [[message_id, r[0]] for r in entry]                
            self._messages_to_return += rec                
              
        # get next
        return_value = self._messages_to_return[0]
        self._messages_to_return.remove(return_value)
        return return_value
        
        
    def _setup_receiver_streams(self):
        ''' sets up the streams for the receiver part of this
            stream
        
            Input:    -
            Output:   -
        '''
        # log
#         logging.info("ECU %s: setup streams" % self._ecu_id)
        
        # setup
        for stream in self.receiver_streams:
            self._receiver.setup_streams(stream)
            
    @property
    
    def _jitter(self):
        return self._jitter_in
    
    @_jitter.setter
    
    def _jitter(self, value):
        try:
            self._sender._jitter = value
            self._receiver._jitter = value
            self._time_sync._jitter = value
        except:
            pass
        self._jitter_in = value
           
    @property
    
    def ecu_id(self):
        return self._ecu_id
               
    @ecu_id.setter    
    
    def ecu_id(self, value):
        self._sender.ecu_id = value
        self._receiver.ecu_id = value
        self._time_sync.ecu_id = value    
        self._ecu_id = value          

    
    def monitor_update(self):
        ''' updates the monitor connected to this ecu
            
            Input:    -
            Output:   monitor_list    RefList    list of MonitorInputs
        '''
        items_1 = len(self.transp_lay.datalink_lay.controller.receive_buffer.items)
        items_2 = self.transp_lay.datalink_lay.transmit_buffer_size
        
        G().mon(self.monitor_list, MonitorInput(items_1, MonitorTags.BT_ECU_RECEIVE_BUFFER, self._ecu_id, self.sim_env.now))
        G().mon(self.monitor_list, MonitorInput(items_2, MonitorTags.BT_ECU_TRANSMIT_BUFFER, self._ecu_id, self.sim_env.now))
        
        self.monitor_list.clear_on_access()  # on the next access the list will be cleared        
        return self.monitor_list.get()

class TeslaSender(object):
    '''
    all sending activities of the tesla communication module are
    performed by this class
    '''
    def __init__(self, sim_env, transport_layer, ecu_id, communication_module, monitor_list=[], jitter=1):        
        ''' Constructor
        
            Input:  sim_env                simpy.Environment        environment of this component    
                    transport_layer        AbstractTransportLayer   transport layer connected to this communication module
                    ecu_id                 string                   id of the ecu sending
                    communication_module   TeslaCommModule          communication module in which this class is
                    monitor_list           RefList                  monitor list passed to monitor  
                    jitter                 float                    random value multiplied on each timeout
            Output: -        
        '''
        
        # passed values
        self._jitter = jitter   
        self._transp_lay = transport_layer
        self._com = communication_module
        
        self.monitor_list = monitor_list            
        self.ecu_id = ecu_id
        self.sim_env = sim_env        
    
        # Initialize parameters
        self._interval_calc = {}  # key: stream_id, value: [start_t, interval]
#         self._interval_times = {}  # key: stream_id, value:  list: [0,0.5,1,...] time interval
#         self._interval_times_original = {}
        
        self._keys = {}  #  key: stream_id, value: Map of keys (from index) key: index, value: Key
        self._t_0 = {}  # key: stream_id, value: Start time of first interval
        self._d = {}  #  key: stream_id, value: disclosure delay
        self._t_int = {}  #  key: stream_id, value: time interval 
    
                                  
    def exchange_first_key(self, stream):
        ''' send key K_0 to all receivers with id rec_id 
            
            Input:    stream    MessageStream    stream for which the key will be exchanged
            Output:   - 
        '''
        # shift the interval   
        self._interval_calc[stream.message_id][0] = self.sim_env.now 
        
        # send to all receivers
        for receiver_id in stream.receivers:
            stream_id = stream.message_id
            
            # generate store
            TeslaCommModule.KX_EXPECTED_NUMBER[stream_id] = len(stream.receivers)

            if stream_id not in TeslaCommModule.KX_ACTUAL_NUMBER: 
                TeslaCommModule.KX_ACTUAL_NUMBER[stream_id] = 0
            
            # generate clear message
            clear_message, uid = self._extract_first_key_information(stream_id, receiver_id)
                                
            # time for encryption
            cipher_size, encryption_time = self._first_key_message_size_time()            
            yield self.sim_env.timeout(encryption_time)
                        
            # encrypt message: key 0 is associated to now
            interval_shift = self.sim_env.now
            clear_message[1] = interval_shift
            encrypted_message = self._encrypt_first_key(receiver_id, clear_message)
                        
            
            
            # send message
            message = self._first_key_message_sendable(encrypted_message, cipher_size, stream_id, uid, receiver_id)                    
            yield self.sim_env.process(self._transp_lay.send_msg(self.ecu_id, can_registration.CAN_TESLA_KEY_EXCHANGE, message))
    
    
    def run_setup(self, streams):
        ''' per defined stream create the specified number of 
            keys 
        
            Input:    streams    list    list of MessageStream objects
            Output:   -
        '''
        receivers = []
        
        # create keys
        for stream in streams:
            self._create_keys(stream)            
            receivers += stream.receivers            
            
        # monitor
        u_id = self._monitor_first_setup(receivers)
            
        # key creation time  
        one_key_gen_time = G().call_or_const(self._com.TESLA_ONE_KEY_CREATION, self._com.TESLA_MAC_KEY_ALGORITHM, self._com.TESLA_MAC_KEY_LEN)
        yield self.sim_env.timeout(len(streams) * one_key_gen_time * self._com.TESLA_KEY_CHAIN_LEN * self._jitter)
        
        # monitor
        self._monitor_second_setup(u_id, receivers)

    
    def transmit(self, message_id, message, receivers):
        ''' this method prepares the message as defined in 
            the tesla standard. It calculates the MAC using the
            key of this interval and sends it to the receivers. This
            MAC will be encryptable once the receiver receives the
            disclosed key which will be sent d intervals later. 
            
            Input:  message_id    integer    id of the message to be sent
                    message       SegData    message to be sent
                    receivers     list       list of receiver ids that should receive this message
            Output: -
        '''
        
        # interval index
        stream_id, d, interval_index = self._extract_transmit_information(message_id)
        
        if interval_index >= self._com.TESLA_KEY_CHAIN_LEN: 
            logging.error("Stream %s: Too less keys in key chain. Tried to send message with key %s but only %s generated\npossible solution decrease the time needed for one key generation (project parameter: t_mac_key_generation_time) or set more keys to generate (caution: memory leak)\n" % (stream_id, interval_index, self._com.TESLA_KEY_CHAIN_LEN))
            
        # calculate MAC
        validation_mac, uid = self._calculate_transmit_mac(stream_id, interval_index, message, receivers)
        
        # time to generate mac
        mac_size, mac_time = self._extract_transmit_size_time(message)        
        yield self.sim_env.timeout(mac_time)
        
        # key k_{i-d}
        k_i_d = self._get_delayed_key(interval_index, stream_id, d)
        
        # send the message to the receiver
        sendable_message = self._transmit_message_sendable(message, interval_index, validation_mac, k_i_d, stream_id, mac_size, receivers, uid)  
        yield self.sim_env.process(self._transp_lay.send_msg(self.ecu_id, message_id, sendable_message))
    
    
    def _calculate_transmit_mac(self, stream_id, interval_idx, message, receivers):
        ''' returns the mac that is calculated for this message. It is calculated
            from the mac key with index interval_idx from the content of the given
            message
            
            Input:  stream_id        integer    id of the message to be sent
                    interval_idx     integer    interval of the current message 
                    message          SegData    message to be transmitted
                    receivers        list       list of receivers for this ecu 
            Output: validation_mac   MAC        encrypted mac for this message        
                    u_id             hex        unique id of this message
        '''
        # determine prf
        k_i = self._keys[stream_id].get_value(interval_idx)
        prf = PRFDummy().prf_from_enum(self._com.TESLA_PRF_MAC_KEY)
        
        # calculate key
        k_s_i = prf(len(k_i.id), k_i.id)
        ky = MACKey(self._com.TESLA_MAC_KEY_ALGORITHM, self._com.TESLA_MAC_KEY_LEN, predefined_id=k_s_i)
        
        # create MAC
        validation_mac = mac(message.get(), ky)   
        
        # monitor
        u_id = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_INIT_TRANSMIT_MESSAGE
        now = self.sim_env.now
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, str(receivers), stream_id, message.get(), len(message), stream_id, u_id))
        
        return validation_mac , u_id
    
    
    def _create_keys(self, stream):
        ''' create one keychain per stream
            
            Start time is the start time of this very ECU
            Interval Duration is the max(RTT, sending_distance) + offset
            Disclosure delay also the one specified
            
            Input:    stream    MessageStream    message stream corresponding to the key chain
            Output:   -
        '''
        
        
        # extract:
        stream_id = stream.message_id
        t_int = stream.sending_interval + 0.001  # Safety offset
        disclosure_delay = stream.disclosure_delay        
            
        # log
#         logging.info("%s: Start key generation stream %s" % (self.ecu_id, stream_id))
                
        # Initialize
        self._t_int[stream_id] = t_int
        self._d[stream_id] = disclosure_delay
        self._keys[stream_id] = RefDict()
#         self._interval_times_original[stream_id] = []
        cur_itv = self.sim_env.now
        self._t_0[stream_id] = cur_itv
        self._interval_calc[stream_id] = [cur_itv, t_int]
        
        # if already calculated reuse keys
        if TeslaCommModule.CREATED_KEYS:
            
#             self._interval_times_original[stream_id] = list(numpy.arange(self.sim_env.now, (self._com.TESLA_KEY_CHAIN_LEN + 2) * t_int + self.sim_env.now, t_int))[1:]            
            self._keys[stream_id] = TeslaCommModule.CREATED_KEYS
#             print("List of length %s and     - use dict %s" % (len(self._interval_times_original[stream_id]), self._keys[stream_id]))
            return
        
        prf_key = PRFDummy().prf_from_enum(self._com.TESLA_PRF_KEY_CHAIN)
        key_len = EnumTrafor().to_value(self._com.TESLA_MAC_KEY_LEN) / 8
        
        # use random value for K_N
        K_N_p_1 = os.urandom(round(EnumTrafor().to_value(self._com.TESLA_MAC_KEY_LEN) / 8))  # k_N        
        cur_key = K_N_p_1  # k_N+1
        idx = self._com.TESLA_KEY_CHAIN_LEN - 1 
        
        # Generate Keys
        print("Running initial key generation %s keys (=loops)" % (self._com.TESLA_KEY_CHAIN_LEN))
        cur_itv = (self._com.TESLA_KEY_CHAIN_LEN + 2) * t_int + self.sim_env.now 
        for i in range(self._com.TESLA_KEY_CHAIN_LEN + 1):   
            cur_itv -= t_int            
            idx = self._com.TESLA_KEY_CHAIN_LEN - i             
#             self._interval_times_original[stream_id].append(cur_itv)
            try: K_i = prf_key(key_len, cur_key.id)
            except: K_i = prf_key(key_len, cur_key)            
            cur_key = MACKey(self._com.TESLA_MAC_KEY_ALGORITHM, self._com.TESLA_MAC_KEY_LEN, predefined_id=K_i)
            self._keys[stream_id].set(idx, cur_key)
           
        # save to reuse 
        TeslaCommModule.CREATED_KEYS = self._keys[stream_id]
        
        # log
        print("Finished initial key generation %s keys (=loops)" % (self._com.TESLA_KEY_CHAIN_LEN))
#         self._interval_times_original[stream_id] = self._interval_times_original[stream_id][::-1]

    
    def _encrypt_first_key(self, receiver_id, clear_message):
        ''' this method encrypts the given message with the
            public key of the receiver with id receiver_id
            
            Input:  receiver_id          string            id of the receiver whose key will be used for encryption
                    clear_message        list              clear message to exchange the first key
            Output: encrypted_message    EncryptedMessage  message after encryption
        '''
        # get key
        public_key = PublicKeyManager().get_key(receiver_id)
        
        # encrypt
        encrypted_message = asy_encrypt(clear_message, public_key)
    
        return encrypted_message
    
    
    def _extract_first_key_information(self, stream_id, receiver_id):
        ''' returns the first MAC key for this stream in the clear
            message that will be sent to the receiver with the
            given id
        
            Input:  stream_id      integer    id of the stream corresponding to the key
                    receiver_id    string     id of the receiver
            Output: clear_messagse list       clear key exchange message
                    u_id           hex        unique identifier for this message
        '''
            
        # first stream MAC key
        k_0 = self._keys[stream_id].get_value(0)

        t_0 = self._interval_calc[stream_id][0] + self._interval_calc[stream_id][1]

        # clear message
        clear_message = [k_0, t_0, stream_id, receiver_id, self._com.TESLA_KEY_CHAIN_LEN]
        msg_size = len(k_0.id) + len(receiver_id) + 6 + 6  # @UnusedVariable

        # monitor
        u_id = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_INIT_EXCHANGE_FIRST_KEY_KN
        now = self.sim_env.now
        message_id = can_registration.CAN_TESLA_KEY_EXCHANGE
        size = self._com.TESLA_KEY_EXCHANGE_CLEAR_SIZE
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, receiver_id, message_id, clear_message, size, stream_id, u_id))  
    
        return clear_message, u_id
    
    
    def _extract_transmit_information(self, message_id):
        ''' extracts the information to transmit the message
            with given stream id message_id
            
            Input:  message_id      integer     id of the message that is to be transmitted
            Output: stream_id       integer     id of the message that is to be transmitted
                    d               integer     delay with which the MAC key for a message sent at time t
                                                will be sent. e.g. message sent at t = 5 then the key
                                                to verify this message is sent in interval 5+d 
                    interval_idx    integer     interval number at which this message is sent  
        '''
        # id, d
        stream_id = message_id
        d = self._d[stream_id]
        
        # interval index
        interval_idx = floor((self.sim_env.now - self._interval_calc[stream_id][0]) / self._interval_calc[stream_id][1])
        
        if interval_idx <= d: interval_idx = d + 1
    
        if interval_idx < 0:
            logging.error("%s %s message_id %s %s" % (self.sim_env.now, message_id, interval_idx, self._interval_calc[stream_id]))
    
        return stream_id, d, interval_idx
    
    
    def _extract_transmit_size_time(self, message):
        ''' this method returns the size of the MAC to be sent and
            the size of the MAC generated
            
            Input:  message    SegData    message that will be sent and hashed by mac
            Output: mac_size   float      size of the MAC generated
                    mac_time   float      time to generate MAC
        '''
        # size
        mac_size = G().call_or_const(self._com.TESLA_MAC_SIZE_TRANSMIT, len(message), self._com.TESLA_MAC_KEY_ALGORITHM, self._com.TESLA_MAC_KEY_LEN, 'ENCRYPTION')
        
        # time
        mac_time = G().call_or_const(self._com.TESLA_MAC_GEN_TIME_TRANSMIT, len(message), self._com.TESLA_MAC_KEY_ALGORITHM, self._com.TESLA_MAC_KEY_LEN)
    
        return mac_size, mac_time
    
    
    def _first_key_message_sendable(self, encrypted_message, cipher_size, stream_id, uid, receiver_id):
        ''' this method will return the sendable version of the first
            key exchange message
        
            Input:     encrypted_message    EncryptedMessage    encrypted first MAC key that will be sent
                       cipher_size          float               size of the message to be sent
                       stream_id            integer             message id of the corresponding stream
                       uid                  hex                 unique id of this message
                       receiver_id          string              id of the ecu at which this message is directed
                       interval_shift       float               time corresponding to the first key index 
            Output:    message              SegData             sendable first key exchange message
        '''
        
        # monitor
        monitor_tag = MonitorTags.CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN
        now = self.sim_env.now
        message_id = can_registration.CAN_TESLA_KEY_EXCHANGE        
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, receiver_id, message_id, encrypted_message, cipher_size, stream_id, uid))  
        
        # message
        message = SegData(encrypted_message, cipher_size)
        message.sender_id = self.ecu_id
        message.dest_id = receiver_id
        
        return message
        
    
    def _first_key_message_size_time(self):
        ''' this method determines the size of the first key 
            exchange message after encryption as well as the 
            time needed for this encryption
            
            Input:    -
            Output:   cipher_size        float    size of the exchange message after encryption
                      encryption_time    float    time needed for the encryption        
        '''
        
        # information
        clear_size = self._com.TESLA_KEY_EXCHANGE_CLEAR_SIZE
        algorithm = self._com.TESLA_KEY_EXCHANGE_ENC_ALGORITHM
        algorithm_option = self._com.TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION
        key_length = self._com.TESLA_KEY_EXCHANGE_KEY_LEN
        
        # size
        cipher_size = G().call_or_const(self._com.TESLA_KEY_EXCHANGE_CIPHER_SIZE, clear_size, algorithm, key_length, 'ENCRYPTION')
        
        # time
        encryption_time = G().call_or_const(self._com.TESLA_KEY_EXCHANGE_ENC_TIME, clear_size, algorithm, key_length, algorithm_option)
    
        return cipher_size, encryption_time
    
    
    def _get_delayed_key(self, interval_index, stream_id, d):
        ''' returns the key corresponding to a message that was 
            sent d intervals earlier. So the disclosed key 
            for an earlier interval
            
            Input:  interval_index    integer        current interval of message to be sent
                    stream_id         integer        id of corresponding stream
                    d                 integer        disclosure delay
            Output: k_i_d             MACKey         key that encrypted MACs sent in interval interval_index - d
        '''
        # correct interval
        if interval_index - d >= 0: 
            k_idx = interval_index - d   
        else: 
            k_idx = False
        
        # key
        if k_idx:
            k_i_d = self._keys[stream_id].get_value(k_idx) 
        else:
            k_i_d = None
        
        return k_i_d         
        
    def _monitor_first_setup(self, receivers):
        ''' this method logs the information for the
            setup of the message stream
            
            Input:  receivers    list    list of receivers for this ecu 
            Output: u_id         hex     unique id for his message
        '''
        # remove duplicates
        receivers = list(set(receivers))
        
        # monitor
        monitor_tag = MonitorTags.CP_SETUP_INIT_CREATE_KEYS
        u_id = uuid.uuid4().hex
        now = self.sim_env.now
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, str(receivers), -1, str([]), 0, -1, u_id))
        
        return u_id     
    
    
    def _monitor_second_setup(self, u_id, receivers):
        ''' this method logs the second part of the 
            information for the setup of the message 
            stream
            
            Input:  u_id         hex     unique id for his message
                    receivers    list    list of receivers for this ecu 
            Output: -
        '''
        monitor_tag = MonitorTags.CP_SETUP_FINISHED_CREATE_KEYS
        now = self.sim_env.now
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, str(receivers), -1, str([]), 0, -1, u_id))
    
    
    def _transmit_message_sendable(self, message, interval_index, validation_mac, k_i_d, stream_id, mac_size, receivers, uid):
        ''' creates the sendable message that will be transmitted to
            the receiving ecus
        
            Input:  message             SegData    message content to be sent
                    interval_index      integer    interval of the current message
                    validation_mac      MAC        mac created to validate this message 
                                                   (encrypted  with key of interval interval_index)
                    k_i_d               MACKey     key corresponding to interval interval_index - d
                    stream_id           integer    id of the message that will be sent
                    mac_size            float      size of the MAC generated from the current content
                    receivers           list       list of receivers for this stream
                    uid                 uid        unique id of this message
            Output: sendable_message    SegData    sendable, prepared message that will be sent       
        '''

        packet = [message.get(), interval_index, validation_mac, k_i_d, self.ecu_id, stream_id]
        packet_size = len(message) + mac_size + 8 + EnumTrafor().to_value(self._com.TESLA_MAC_KEY_LEN) / 8
        
        sendable_message = SegData(packet, packet_size)
        sendable_message.sender_id = self.ecu_id
        sendable_message.dest_id = receivers        
        
        # monitor
        monitor_tag = MonitorTags.CP_MACED_TRANSMIT_MESSAGE
        now = self.sim_env.now
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, str(receivers), -1, str([]), 0, stream_id, uid))
    
#         logging.info("%s - %s: Sending Stream %s to %s" % (self.sim_env.now, self.ecu_id, stream_id, packet))  
    
        return sendable_message
    
class TeslaReceiver(object):
    '''
    all receiving activities of the TESLA communication module are
    performed by this class
    '''
    
    def __init__(self, env, transport_layer, ecu_id, communication_module, monitor_lst=[], jitter=1):    
        ''' Constructor
        
            Input:  sim_env                simpy.Environment        environment of this component    
                    transport_layer        AbstractTransportLayer   transport layer connected to this communication module
                    ecu_id                 string                   id of the ecu sending
                    communication_module   TeslaCommModule          communication module in which this class is
                    monitor_lst           RefList                  monitor list passed to monitor  
                    jitter                 float                    random value multiplied on each timeout
            Output: -        
        '''    
        
        # passed parameters
        self._jitter = jitter     
        self._transp_lay = transport_layer
        self._com = communication_module        
        self.monitor_list = monitor_lst  
        self.ecu_id = ecu_id
        self.sim_env = env
        
        # expected number of keyexchanges
        self.expected_key_exchanges = 0
        
        
        # helper
        self._disclosed_key_indices = {}
        self._last_key = {}  # Last key that was received
        self._last_key_idx = {}  # Index of last received key
        self.d_t = {}  # D_t delay towards the communication partner
        self.k_0 = {}  # k_0 for the stream
        self.t_0 = {}  # Start interval for this stream
        self._t_int = {}  # time interval depending on stream_id
        self._d = {}  # key disclosure delay
        self._buffer = {}  # key stream, value: buffered messages

        # public encryption key
        self.private_key, self.public_key = asy_get_key_pair(self._com.TESLA_KEY_EXCHANGE_ENC_ALGORITHM, self._com.TESLA_KEY_EXCHANGE_KEY_LEN, self._com.TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION)
        PublicKeyManager().add_key(self.ecu_id, self.public_key)
        
    
    def process(self, sender_id, message_id, message_data):
        ''' this method receives the messages from the communication module
            and processes it
            
            Input:  sender_id                 string     id of the sender of the message
                    message_id                integer    id of the message that was received
                    message_data              object     message that was received
            Output: authenticated_messages    list       list of messages that were authenticated on this receiving period
        '''
        
        # key exchange
        if message_id == can_registration.CAN_TESLA_KEY_EXCHANGE:
            yield self.sim_env.process(self._handle_key_exchange(sender_id, message_data))
        # simple message
        else:
            authenticated_messages = yield self.sim_env.process(self._handle_incoming_message(sender_id, message_data, message_id))
            return authenticated_messages
    
    
    def setup_streams(self, stream):
        ''' initializes the information from the stream by
            assigning variables that were set in the stream
            to the corresponding dictionary variables
            It sets the start time of the stream, the width of
            the sending interval as well as the disclosure delay
            
            Input:    stream    MessageStream    stream that will be initialized
            Output:    -
        '''
        self.t_0[stream.message_id] = stream.start_time
        self._t_int[stream.message_id] = stream.sending_interval
        self._d[stream.message_id] = stream.disclosure_delay
        
    @ try_ex
    def _extend_receive_buffer(self, valid, sender_id, message_id, message_data, interval_idx, u_id):
        ''' if all conditions are fulfilled this method
            extends the receiving buffer by the incoming
            message
            
            Input:  valid           boolean        true if the received message fulfills all three defined criteria
                                                     (see _handle_incoming_message)
                    sender_id       string         id of the sender of the message
                    message_id      integer        id of the message that was received
                    message_data    object         message that was received
                    interval_idx    integer        interval of the received message
                    u_id            hex            unique id of the received message
            Output: bool            boolean        true if this message was buffered successfully 
            
        '''
        
        # stop if conditions not fulfilled
        if not (valid):  return False
        
        # extend dictionary
        G().force_add_dict_list(self._buffer, message_id, message_data.get())
        
        # monitor
        monitor_tag = MonitorTags.CP_BUFFERED_SIMPLE_MESSAGE
        now = self.sim_env.now
        message = message_data.get()
        size = len(message_data)
        monitor_input = MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, message, size, message_id, u_id)
        G().mon(self.monitor_list, monitor_input)  
        
        # successful
        return True
        
    
    def _handle_incoming_message(self, sender_id, message_data, message_id):
        ''' incoming messages will have to prove three conditions to
            be considered authenticated.
            i. safe packet test: the message containing the key for this message
                                 must not be disclosed at the moment this ecu receives 
                                 this message
            ii. new key index:   the received key must not yet have been used
            iii. key legid:      the current key must be derivable from a key that was
                                 received earlier by using the arranged Pseudorandom function
            
            Input:  sender_id                 string     id of the sender of the message
                    message_id                integer    id of the message that was received
                    message_data              object     message that was received
            Output: authenticated_messages    list       list of messages that were authenticated on this receiving period
        '''
        
        # extract packet
        content = message_data.get()
        message, interval_idx, val_mac, k_i_d = content[:4]  # @UnusedVariable
        t_arrival = self.sim_env.now

        # Monitor
        u_id = self._monitor_incoming_message(sender_id, message_id, message_data)
        
        # safe packet test
        safe_condition = self._is_safe_packet(interval_idx, t_arrival, sender_id, message_id)
        
        # new key idx test
        new_key_condition = self._is_new_key_index(interval_idx, message_id)
        
        # key verification test
        key_verified_condition = yield self.sim_env.process(self._is_key_legid(k_i_d, interval_idx, message_id, sender_id))
        
        
        # buffer message
        valid = True  # safe_condition and new_key_condition and key_verified_condition
            
        if not self._extend_receive_buffer(valid, sender_id, message_id, message_data, interval_idx, u_id): return False

        # get verified messages: Index i-d
        authenticated_messages = yield self.sim_env.process(self._verified_messages(k_i_d, message_id, interval_idx - self._d[message_id]))
        
        # safe last key and monitor
        self._set_last_information_incoming_message(message_id, k_i_d, interval_idx, authenticated_messages, u_id)
        
        # return authenticated
        return authenticated_messages
                
    
    def _handle_key_exchange(self, sender_id, message_data):
        ''' this method handles the key exchange message that was sent
            to exchange the initial key K_0 that is used to perform the 
            first message validity checks
            
            Input:  sender_id                 string     id of the sender of the message
                    message_data              object     message that was received
            Output: -
        '''
        
        # decrypt message
        encrypted_message = message_data.get()
        clear_message = asy_decrypt(encrypted_message, self.private_key, self.sim_env.now)   
        
        # monitor
        u_id = self._monitor_key_exchange_first(clear_message, sender_id, message_data)
        
        # decryption time
        yield self.sim_env.timeout(self._key_exchange_decryption_time()) 
        
        # monitor
        self._monitor_key_exchange_second(clear_message, sender_id, u_id)
        if clear_message == None: return    
            
        # save the last key
        self._save_key_exchange_information(clear_message)         
    
        # set confirmed
        self._com.set_up = True
        
        # notify all done
        TeslaCommModule.KX_ACTUAL_NUMBER[clear_message[2]] += 1
        if TeslaCommModule.KX_ACTUAL_NUMBER[clear_message[2]] == TeslaCommModule.KX_EXPECTED_NUMBER[clear_message[2]]:
            if clear_message[2] in TeslaCommModule.KX_SETUP_NOTIFY_STORES:
                TeslaCommModule.KX_SETUP_NOTIFY_STORES[clear_message[2]].put(True)
            
        if False: yield self.sim_env.timeout(0)
        
    
    def _is_key_legid(self, k_i_d, i_d, stream_id, sender_id):
        ''' this method checks if the received key is legid. i.e.
            if the received key can be derived from a earlier
            received key by repeatedly applying the defined PRF 
            on it
            
            Input:  k_i_d           MACKey       key that encrypts the mac of the message that was 
                                                 received in the i-d th interval 
                    i_d             integer      index of the interval to which the received key corresponds (i-d)  
                    stream_id       integer      id of the message that was received  
                    sender_id       string       id of the sender of the message 
            Output: bool            boolean      true if the key is legid
        '''         
        
        monitor_tag = MonitorTags.CP_INIT_CHECK_KEY_LEGID
        now = self.sim_env.now
        uid = uuid.uuid4().hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, stream_id, str([]), len(k_i_d.id), stream_id, uid))  
            
        
        try:            
            # key used for verification and its index
            k_v = self._last_key[stream_id]
            v = self._last_key_idx[stream_id]
            if v == 0: v = self._d[stream_id]  # first run
            
            # prf and key length used
            prf = PRFDummy().prf_from_enum(self._com.TESLA_PRF_KEY_CHAIN)
            key_length = EnumTrafor().to_value(self._com.TESLA_MAC_KEY_LEN) / 8
            
            # number of loops to get same key
            received_idx = i_d
            saved_idx = v
            nr_loops = received_idx - saved_idx
            if nr_loops < 0: 
                nr_loops = 0
                
            # check if K_v = F^{i-d-v}(K_{i-d}) holds
            current_key_id = k_i_d.id
            for i in range(nr_loops):  # @UnusedVariable
                current_key_id = prf(key_length, current_key_id)
            comparison_key_id = current_key_id
            
            # timeout: nr_loops * time for one prf
            prf_time = G().call_or_const(self._com.TESLA_KEY_LEGID_PRF_TIME, self._com.TESLA_KEY_LEGID_MAC_ALGORITHM, self._com.TESLA_KEY_LEGID_MAC_KEY_LEN)

            yield self.sim_env.timeout(prf_time * nr_loops)            
            
            # monitor
            monitor_tag = MonitorTags.CP_CHECKED_KEY_LEGID
            now = self.sim_env.now
            G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, stream_id, str([]), len(k_i_d.id), stream_id, uid))  
            
            if nr_loops == 0:
                return True 
            
            # result
            return comparison_key_id == k_v.id
        except:
            prf_time = G().call_or_const(self._com.TESLA_KEY_LEGID_PRF_TIME, self._com.TESLA_KEY_LEGID_MAC_ALGORITHM, self._com.TESLA_KEY_LEGID_MAC_KEY_LEN)

            ECULogger().log_traceback()
            return False
        
    
    def _is_new_key_index(self, index, stream_id):
        ''' true if this key index is new within this stream. 
            Can get twice the same key, but not more
            
            Input:  index        integer    index of key that will be checked
                    stream_id    integer    id of message that was received
            Output: bool         boolean    true if the given key is new
        '''
        return True  # Abstraction assume correct key sent
        
        # 1. kenne delay zum sender (also sending time)
        
        # 2. pruefe hat er schon neuen key disclosed?
        
        # 3. wenn ja dann checke ob der empfangene key neu ist. sollte so sein
        
        # 4. wenn nein dann alles ok und true
        
        
        try:
            # key already existent
            if index in self._disclosed_key_indices[stream_id]:
                result = False
                
            # new key
            else:
                self._disclosed_key_indices[stream_id].append(index)
                result = True
        except:
            result = True
            
        # add to existent keys
        G().force_add_dict_list(self._disclosed_key_indices, stream_id, index)
        
        # result
        return result
        
    
    def _is_safe_packet(self, interval_idx, t_arrival, sender_id, stream_id):
        ''' checks if the received message was received before the sender is
            scheduled to send the message that dicloses this messages key. 
            If this condition is fulfilled the message is considered a safe packet.
            
            Input:  interval_idx    integer    index of the interval corresponding to the received message
                    t_arrival       float      time when the current message was received
                    sender_id       string     id of the ecu that sent this message
                    stream_id       integer    id of the message that was received
            Output: bool            boolean    true if the message is a safe packet       
        
            Problem: on setup there is way less traffic when the timing synchronization is done. 
                     So on this check when there is a lot traffic this method returns False
                     Therefore skip this condition currently...
        '''
        return True
        
        # upper bound on sender clock
        t_upper = t_arrival + self.d_t[sender_id]

        
        # max Sender interval
        x = floor((t_upper - self.t_0[stream_id]) / self._t_int[stream_id])
        
        # check if sender already disclosed key for this packet (if not then ok)
        # print(x <= (interval_idx + self._d[stream_id]))
        # print("Upper %s, Interval  %s, t_0: %s, itv_idx: %s, x: %s, d: %s" % (t_upper, self._t_int[stream_id], self.t_0[stream_id], interval_idx, x, self._d[stream_id]))
        return x <= (interval_idx + self._d[stream_id])
        
    
    def _key_exchange_decryption_time(self):
        ''' this method calculates the decryption time needed
            to decrypt the received key exchange message
            
            Input:   -
            Output:  decryption_time    float    time needed to decrypt the key exchange message
        '''
        # information
        algorithm = self._com.TESLA_KEY_EXCHANGE_ENC_ALGORITHM
        algorithm_option = self._com.TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION
        key_length = self._com.TESLA_KEY_EXCHANGE_KEY_LEN
        clear_size = self._com.TESLA_KEY_EXCHANGE_CLEAR_SIZE
        
        #  size
        cipher_size = G().call_or_const(self._com.TESLA_KEY_EXCHANGE_CIPHER_SIZE, clear_size, algorithm, key_length, 'ENCRYPTION')
        
        # time
        decryption_time = G().call_or_const(self._com.TESLA_KEY_EXCHANGE_DEC_TIME, cipher_size, algorithm, key_length, algorithm_option)
        
        return decryption_time
        
    
    def _monitor_incoming_message(self, sender_id, message_id, message_data):
        ''' this method monitors information about the incoming messages
            
            Input:  sender_id                 string     id of the sender of the message
                    message_id                integer    id of the message that was received
                    message_data              object     message that was received
            Output: u_id                      hex        unique id corresponding to the current message
        '''
        # Monitor
        u_id = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_RECEIVED_SIMPLE_MESSAGE
        now = self.sim_env.now
        message = message_data.get()
        size = len(message_data)
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, message, size, message_id, u_id))  
        
        return u_id
        
    
    def _monitor_key_exchange_first(self, clear_message, sender_id, message_data):
        ''' monitors the first part of the exchange message
        
            Input:  clear_message    list       clear exchange message
                    sender_id        string     id of the sender of the message
                    message_data     object     message that was received  
            Output: u_id             hex        unique id corresponding to this message
        '''
        # monitor
        if clear_message != None:
            u_id = uuid.uuid4().hex
            monitor_tag = MonitorTags.CP_RECEIVED_EXCHANGE_FIRST_KEY_KN
            now = self.sim_env.now
            message_id = can_registration.CAN_TESLA_KEY_EXCHANGE
            content = message_data.get()
            size = len(message_data)
            G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, content, size, -1, u_id))  
       
     
    def _monitor_key_exchange_second(self, clear_message, sender_id, u_id):
        ''' monitors the second part of the exchange message 
        
            Input:  clear_message    list       clear exchange message
                    sender_id        string     id of the sender of the message
                    u_id             hex        unique id corresponding to this message
            Output: -
        '''
        if clear_message != None:
            monitor_tag = MonitorTags.CP_DECRYPTED_EXCHANGE_FIRST_KEY_KN
            now = self.sim_env.now
            message_id = can_registration.CAN_TESLA_KEY_EXCHANGE
            size = self._com.TESLA_KEY_EXCHANGE_CLEAR_SIZE
            G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, size, -1, u_id))  
    
     
    def _monitor_same_mac_verification(self, pre_time, post_time, k_i_d, message):
        ''' this method monitors the information when the verification of the 
            MACs was successful in the check of the messages in the buffer
        
            Input:  pre_time     float          time before the MAC creation of this message  
                    post_time    float          time after the MAC creation of this message  
                    k_i_d        MACKey         key that encrypts the mac of the message that was 
                                                received in the i-d th interval 
                    message      object         current message from the buffer
            Output: -
        '''
        
        # monitor before encryption
        u_id = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_INIT_VERIFYING_BUFFER_MESSAGE
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, pre_time, message[-2], message[-1], str([]), len(k_i_d.id), message[-1], u_id))  
        
        # monitor after encryption
        monitor_tag = MonitorTags.CP_FINISHED_VERIFYING_BUFFER_MESSAGE
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, post_time, message[-2], message[-1], str([]), len(k_i_d.id), message[-1], u_id))  
    
    
    def _save_key_exchange_information(self, clear_message): 
        ''' this method saves the information received in the key exchange
            information: k_0 first key of the key chain, t_0 start time
            of the first interval with index 0.
            
            Input:  clear_message    list       clear exchange message
            Output: -            
            '''
         
        
         
        # extract from 
        k_0, t_0, stream_id = clear_message[:3]
        
        # save information
        self.k_0[stream_id] = k_0
        self._last_key[stream_id] = k_0
        self._last_key_idx[stream_id] = 0
        self.t_0[stream_id] = t_0
        
    
    def _set_last_information_incoming_message(self, message_id, k_i_d, interval_idx, authenticated_messages, u_id):
        ''' Sets the last received key that is used afterwards to
            perform the key legitimacy check on the next received message
            
            Input:  message_id                integer        id of the last received message
                    k_i_d                     MACKey         key corresponding to the currently received message
                    interval_idx              integer        index of the interval of the received message
                    authenticated_messages    list           list of messages that were successfully authenticated
                    u_id                      hex            unique id corresponding to the received message
            Output: -
        '''     
        
        # save last key
        self._last_key[message_id] = k_i_d
        self._last_key_idx[message_id] = interval_idx
        
        # monitor received elements
        for msg in authenticated_messages:
            monitor_tag = MonitorTags.CP_RETURNED_AUTHENTICATED_SIMPLE_MESSAGE
            now = self.sim_env.now            
            G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, msg[-2], msg[-1], msg, 0, msg[-1], u_id))  
            
        # log received
#         logging.info("\treceived message %s when got key %s" % (str(authenticated_messages), interval_idx - self._d[message_id]))
        
    
    def _verified_messages(self, k_i_d, stream_id, i_d):
        ''' this method returns all messages that are in the buffer
            for the given stream_id and that can be decrypted given
            the disclosed received key with index i-d
        
            Input:  k_i_d                   MACKey       key that encrypts the mac of the message that was 
                                                         received in the i-d th interval 
                    i_d                     integer      index of the interval to which the received key corresponds (i-d)  
                    stream_id               integer      id of the message that was received  
            Output: authenticated_messages  list         list of messages that were received   
        '''
        # initialize
        authenticated_messages = []
        if stream_id not in self._buffer: return        
        
        # buffer and prf
        buffer = self._buffer[stream_id]
        prf = PRFDummy().prf_from_enum(self._com.TESLA_PRF_MAC_KEY)
        
        # calculate MAC key from key k_{i-d}
        idd = prf(len(k_i_d.id), k_i_d.id)
        k_s_i_d = MACKey(self._com.TESLA_MAC_KEY_ALGORITHM, self._com.TESLA_MAC_KEY_LEN, idd)

        for message in buffer:
            
            # calculate MAC
            val_mac = mac(message[0], k_s_i_d)            
            pre_time = self.sim_env.now
            
            # time to generate the MAC
            mac_size = G().call_or_const(self._com.TESLA_MAC_SIZE_TRANSMIT, len(message[0]), self._com.TESLA_MAC_KEY_ALGORITHM, self._com.TESLA_MAC_KEY_LEN, 'ENCRYPTION')  # @UnusedVariable
            mac_time = G().call_or_const(self._com.TESLA_MAC_GEN_VERIFY_TIME_TRANSMIT, len(message[0]), self._com.TESLA_MAC_KEY_ALGORITHM, self._com.TESLA_MAC_KEY_LEN)
            yield self.sim_env.timeout(mac_time)
            
            # saved Mac
            saved_mac = message[2]
            post_time = self.sim_env.now
            
            
            # if same save
            if same_mac_ct(val_mac, saved_mac):         
                self._monitor_same_mac_verification(pre_time, post_time, k_i_d, message)                
                authenticated_messages.append(message)
                     
        for message in authenticated_messages:
            self._buffer[stream_id].remove(message)
        
        return authenticated_messages
        
class TeslaSynchronizeTime(object):
    ''' synchronizes the time between two communication partners '''
    
    def __init__(self, sim_env, transport_layer, ecu_id, sender, receiver, monitor_lst=[], jitter=1):        
        ''' Constructor
        
            Input:  sim_env                simpy.Environment        environment of this component    
                    transport_layer        AbstractTransportLayer   transport layer connected to this communication module
                    ecu_id                 string                   id of the ecu sending
                    sender                 TeslaSender              sender class of the communication module linked to this ECU
                    receiver               TeslaReceiver            receiver class of the communication module linked to this ECU
                    monitor_lst            RefList                  monitor list passed to monitor  
                    jitter                 float                    random value multiplied on each timeout
            Output: -        
        '''    
        # passed parameters
        self._jitter = jitter    
        self._sender = sender 
        self._receiver = receiver  
        self._transp_lay = transport_layer        
        self.monitor_list = monitor_lst 
        self.ecu_id = ecu_id
        self.sim_env = sim_env
        self.time_sync_done_sync = simpy.Store(self.sim_env, capacity=1)    
        
        # message indicator
        self.init_id = {}
        
        # expected number of response messages
        self.expected_sync_messages = 0
        self.received_messages = 0
        
    
    def receiver_sync_init(self, destination_id):
        ''' send the synchronization message to the destination ECU.
            Add a unique id to be able to measure the roundtrip time
            belonging to this very message
            
            Input:     destination_id    string    id of the ECU that is to be synchronized with
            Output:    -
        '''        
        # message creation
        self.init_id[destination_id] = uuid4()
        message = SegData([self.sim_env.now, self.init_id[destination_id]], 5)
        message.dest_id = destination_id
        
        # monitor
        monitor_tag = MonitorTags.CP_SEND_SYNC_MESSAGE
        now = self.sim_env.now
        message_id = can_registration.CAN_TESLA_TIME_SYNC
        size = len(message)
        uid = uuid.uuid4().hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, destination_id, message_id, message.get(), size, -1, uid))
                
        # send sync message
        yield self.sim_env.process(self._transp_lay.send_msg(self.ecu_id, can_registration.CAN_TESLA_TIME_SYNC, message))
    
    
    def  process(self, sender_id, message_id, message):
        ''' this method receives the messages from the communication module
            and processes it
            
            Input:  sender_id                 string     id of the sender of the message
                    message_id                integer    id of the message that was received
                    message                   object     message that was received
            Output: authenticated_messages    list       list of messages that were authenticated on this receiving period
        '''
        # time sync message
        if message_id == can_registration.CAN_TESLA_TIME_SYNC:
            yield self.sim_env.process(self._handle_tesla_time_sync(message, sender_id))
            
        # response to time sync
        if message_id == can_registration.CAN_TESLA_TIME_SYNC_RESPONSE:
            self._handle_tesla_time_sync_finished(message, sender_id)
    
    
    def _handle_tesla_time_sync(self, message, sender_id):
        ''' sender receives the receiver time and answers with 
            a sync response message
            
            Input:  message      SegData    time sync response message that was received
                    sender_id    string     id of the sending ecu
            Output: -
        '''               
        # check destination
        if not message.dest_id == self.ecu_id: return
        
        # extract information
        t_rec, idd = message.get()[:2]
        t_send = self.sim_env.now
        
        # generate response
        message = SegData([t_rec, t_send, idd], 8)
        message.dest_id = sender_id
        
        # monitor
        self._monitor_time_sync(sender_id, message)
        
        yield self.sim_env.process(self._transp_lay.send_msg(self.ecu_id, can_registration.CAN_TESLA_TIME_SYNC_RESPONSE, message))
        
    
    def _handle_tesla_time_sync_finished(self, message, sender_id):
        ''' receiver receives answer from sender
            and sets the time difference at the receiver class
            
            Input:  message      SegData    time sync response message that was received
                    sender_id    string     id of the sending ecu
            Output: -  
        '''
        # extract information
        clear_msg = message.get()        
        t_received, t_sent, idd = clear_msg[:3]
            
        # check if the one this ecu sent
        if sender_id in self.init_id and idd == self.init_id[sender_id]:       
            self._monitor_time_sync_finished(sender_id, message)   
            self._receiver.d_t[sender_id] = t_sent - t_received   
            self.received_messages += 1
            
            # notify that sync complete            
            TeslaCommModule.KX_ACTUAL_RECS[sender_id].append(self.ecu_id)
            if sorted(TeslaCommModule.KX_EXPECTED_RECS[sender_id]) == sorted(TeslaCommModule.KX_ACTUAL_RECS[sender_id]):
                TeslaCommModule.KX_TIME_SYNC_DONE_STORES[sender_id].put(True)
        
    
    def _monitor_time_sync(self, sender_id, message):
        ''' this method monitors the received time sync message
        
            Input:  message      SegData    time sync response message that was received
                    sender_id    string     id of the sending ecu
            Output: -        
        '''
        # first
        monitor_tag = MonitorTags.CP_RECEIVE_SYNC_MESSAGE
        now = self.sim_env.now
        message_id = can_registration.CAN_TESLA_TIME_SYNC
        uid = uuid.uuid4().hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, message.get(), len(message), -1, uid))  
        
        # second
        monitor_tag = MonitorTags.CP_SEND_SYNC_RESPONSE_MESSAGE
        now = self.sim_env.now
        message_id = can_registration.CAN_TESLA_TIME_SYNC_RESPONSE
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, message.get(), len(message), -1, uid))  
    
    
    def _monitor_time_sync_finished(self, sender_id, message):
        ''' this method monitors the received time sync finished 
            message
        
            Input:  message      SegData    time sync response message that was received
                    sender_id    string     id of the sending ecu
            Output: -        
        '''
        # monitor
        monitor_tag = MonitorTags.CP_RECEIVE_SYNC_RESPONSE_MESSAGE
        now = self.sim_env.now
        message_id = can_registration.CAN_TESLA_TIME_SYNC_RESPONSE
        uid = uuid.uuid4().hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, message.get(), len(message), -1, uid))
        
class PRFDummy(Singleton):
    '''
    contains prf functions that are not safe but fulfill the 
    condition of unambiguity
    '''
    def __init__(self):
        ''' Constructor'''
        pass
    
    
    def prf_from_enum(self, prf):
        ''' given a PRF Enum this message returns 
            the corresponding method that can be
            used as prf
            
            Input:    prf        PRF         this enum indicates which prf to return
            Output:   dummyprf   function    function corresponding to the requested ecu 
        '''
        if PRF.DUMMY == prf:
            return self._dummy_prf
        
        if PRF.DUMMY_SHA == prf:
            return self._dummy_prf_sha
    
    
    def _dummy_prf(self, des_out_len, seed):
        ''' this prf simply applies a hashing with
            md5 and concatenates the result until
            the desired length is reached
            
            Input:  des_out_len    integer  desired length of the output of this method
                    seed           bytes    this byte string is used and hashed
            Output: cur_hash       bytes    unique byte sequence of length des_out_len resulting from 
                                            the seed
        '''
        # nr of chuncks to reach length
        nr_chunks = math.ceil(des_out_len / 16)
        
        # simply hash 
        cur_hash = b""
        hashimo = seed
        for i in range(nr_chunks):  # @UnusedVariable
            hashimo = md5(bytes(str(hashimo), 'utf-8')).digest()
            cur_hash += hashimo
        
        return cur_hash[:round(des_out_len)]
        
    
    def _dummy_prf_sha(self, des_out_len, seed):
        ''' this prf simply applies a hashing with
            sha and concatenates the result until
            the desired length is reached
            
            Input:  des_out_len    integer  desired length of the output of this method
                    seed           bytes    this byte string is used and hashed
            Output: cur_hash       bytes    unique byte sequence of length des_out_len resulting from 
                                            the seed
        '''
        # nr of chuncks to reach length
        nr_chunks = math.ceil(des_out_len / 16)
        
        # simply hash 
        cur_hash = b""
        hashimo = seed
        for i in range(nr_chunks):  # @UnusedVariable
            hashimo = sha1(bytes(str(hashimo), 'utf-8')).digest()
            cur_hash += hashimo
        
        return cur_hash[:round(des_out_len)]
    
class RefDict(object):
    ''' wraps a dictionary into an object'''
    
    def __init__(self):
        self._content = {}
    
    def set(self, ky, val):
        self._content[ky] = val
    
    def get_value(self, ky):
        return self._content[ky]
    
    def get(self):
        return
    
    
# class KeyChainReference(tools.singleton.Singleton):
#     ''' this class holds a key chain of a certain length. If requested
#         it returns a keychain of  '''
#     def 
#     
#     def request_keys(self, key_length):
