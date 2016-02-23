from components.base.ecu.software.abst_comm_layers import AbstractCommModule
from components.base.ecu.software.impl_physical_layers import StdPhysicalLayer
from components.base.ecu.software.impl_datalink_layers import StdDatalinkLayer
from components.base.ecu.software.impl_transport_layers import FakeSegmentTransportLayer
from tools.general import RefList, General as G
from config import project_registration as proj, can_registration
from components.security.encryption.encryption_tools import compress, mac, MACKey, decompress, \
    certificate_trustworthy, sym_get_key, sym_encrypt, sym_decrypt, EncryptionSize
from enums.tls_enums import TLSContentType, \
    CompressionMethod, TLSCertificateType, KeyexchangeAlgorithm, TLSState, \
    TLSConnectionEnd, TLSCipherSuite, TLSCipherType
from components.base.message.abst_bus_message import SegData
import os
import uuid
from enums.sec_cfg_enum import AsymAuthMechEnum, CAEnum, \
    AuKeyLengthEnum, EnumTrafor, HashMechEnum
import simpy
from config import timing_registration as time
from components.security.encryption import encryption_tools
from components.security.certification.cert_manager import CertificateManager
from components.security.certification.certification_authority import CAHierarchy
import logging
from _md5 import md5
from enums.ecu_tls_structs import TLSPlaintext, \
    TLSSecurityParameter, TLSCompressed, TLSCiphertext, GenericStreamCipher, \
    GenericBlockCipher, GenericAEADCipher, SignatureAndHashAlgorithm
from io_processing.surveillance_handler import MonitorInput, MonitorTags
from config.specification_set import GeneralSpecPreset
from tools.singleton import Singleton
import sys
import pickle


class TLSCommModule(AbstractCommModule):
    ''' This class implements a secure communication
        module, that enables secure communication between
        several ECUs via TLS 
    
        It's tasks are separated along their functionality. So the record layer
        is the layer used to send and receive messages. On top of this layer 
        the Handshake, ChangecipherSpec, the Alert and the Application messages
        are used. All of those components are implemented in an own class
    '''
    CERT_REUSE = {}  # to save memory only one certificate is created
    CERT_LIST_REUSE = {}  # to save memory only one certificate is created
    PRIV_KEY_REUSE = {}  # to save memory only one certificate is created
    RANDOM_BYTES = {}  # to save memory random bytes are saved only once
    KX_EXPECTED_NUMBER = {}  # key: stream id value: expected number of receivers for this stream
    KX_SETUP_NOTIFY_STORES = {}  # key: stream id value: simpy store, continuing at sender when security information was exchanged with all receivers
    KX_ACTUAL_NUMBER = {}  # key: stream_id, value number of receivers that already were granted for this stream
    CNT = 0
    
    
    def __init__(self, sim_env, ecu_id):
        ''' Constructor
            
            Input:  ecu_id         string                   id of the corresponding AbstractECU
                    sim_env        simpy.Environment        environment of this component
            Output:  -
        '''
        AbstractCommModule.__init__(self, sim_env)

        # passed parameters
        self._ecu_id = ecu_id
        self.monitor_lst = RefList()
        self._streams = []
        self._jitter_in = 1

        # initialize layers
        self._init_layers(self.sim_env, self.MessageClass)
        self._init_sublayers()
        
        # initial parameters
        self._sync = simpy.Store(self.sim_env, capacity=1)
        
    def add_stream(self, new_stream):
        ''' adds a stream to the list of registered
            streams in the simulation
        
            Input:    new_stream    MessageStream    stream to be added
            Output:   -    
        '''
        self._streams.append(new_stream)
        TLSCommModule.KX_EXPECTED_NUMBER[new_stream.message_id] = len(new_stream.receivers)
        TLSCommModule.KX_ACTUAL_NUMBER[new_stream.message_id] = 0
    
    def receive_msg(self):
        ''' receives messages via the TLS mechanism. Therefore
            it first uses the record layer to receive the messages.
            Once the messages are received they are forwarded to 
            the class responsible for the received protocol. 
            (i.e. Handshake, Alert, ChangeCipherSpec or Application)
                        
            Input:     -
            Output:    message_data    object/string/...    message that was received
                       message_id      integer              id of received message
        '''
        
        while True:
            # receive
            [message_id, message_data] = yield self.sim_env.process(self.transp_lay.receive_msg())        

            # not directed to this ECU
            if self._ecu_id != message_data.dest_id: continue

            # extract from record layer
            message = message_data.get()
            message_clear = yield self.sim_env.process(self._record.receive(message_id, message_data.get(), message_data.sender_id))            

            # message None -> not encryptable
            if message_clear == None: continue

            # handle messages
            if message[0] == TLSContentType.HANDSHAKE:
                yield self.sim_env.process(self._handshake.process(message_data.sender_id, message_id, message_clear))
             
            if message[0] == TLSContentType.CHANGE_CIPHER_SPEC:
                yield self.sim_env.process(self._change_spec.process(message_data.sender_id, message_id, message_clear))
                 
            if message[0] == TLSContentType.APPLICATION_DATA:
                return self._app_data.process(message_data.sender_id, message_id, message_clear)
                 
            if message[0] == TLSContentType.ALERT:
                self._alert.process(message_data.sender_id, message_id, message_clear)

        # pass upwards
        return [message_id, message_data]
    
    def notify_receivers_ready(self, stream_id):
        ''' started in a simpy process this method waits until all receivers of the stream with given stream_id
            have received the finished message and are ready for the exchange of application data
        
            Input:    stream_id    integer        id of the stream to wait for
            Output:   - 
        '''
        if stream_id not in TLSCommModule.KX_SETUP_NOTIFY_STORES:
            TLSCommModule.KX_SETUP_NOTIFY_STORES[stream_id] = simpy.Store(self.sim_env, capacity=1)
        
        yield TLSCommModule.KX_SETUP_NOTIFY_STORES[stream_id].get()
        del TLSCommModule.KX_SETUP_NOTIFY_STORES[stream_id]

    def send_msg(self, sender_id, message_id, message):
        ''' this  method checks if a session is available
            for the stream with id message id. If that is not
            the case the handshake protocol is initialized. Until
            this protocol is done messages with this id are dropped.
            Once it is complete they are forwarded securely
            
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
            Output: -
        
        '''
        
        # determine receivers
        receivers = self._get_receivers(message_id)

        for receiver in receivers:
            
            # if currently handshake for this stream, drop message
            if self._handshake.running(receiver, message_id):  return
            
            # session available: simply transmit 
            if self._session_available(receiver, message_id):
                self._monitor_session_available(message_id, message, receiver) 
                yield self.sim_env.process(self._record.send(sender_id, message_id, message, TLSContentType.APPLICATION_DATA, receiver, message_id))
            
            # initialize session
            else:                
                yield self.sim_env.process(self._handshake.send_client_hello(sender_id, message_id, receiver))
                
    def _get_receivers(self, message_id):        
        ''' returns all receivers of streams with the given message id
            where this ecu is the sender 
            
            Input:    message_id    integer    id of message to be sent
            Output:   receivers     list       list of receivers for this stream        
        '''
        for stream in self._streams:
            if stream.message_id == message_id and stream.sender_id == self._ecu_id:
                return stream.receivers
        return []
        
    def _init_layers(self, sim_env, MessageClass):
        ''' initialize all software layers
        
            Input:    sim_env        simpy.Environment    environment of this component
                      MessageClass   AbstractBusMessage   class that is used for sending
            Output:  - 
        '''
        
        # create Layers
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
        ''' each functionality is handled in an own class. Sending and receiving
            is performed in the record layer. On top of this the Handshake, Alert
            ChangeCipherSpec and the application Layer are handled in the respective
            class
            
            Input:    -
            Output:   -
        '''
        # layers
        self._record = TLSRecordLayer(self.sim_env, self.transp_lay, self._ecu_id, self.monitor_lst, self._jitter_in)
        self._handshake = TLSHandshake(self.sim_env, self._record, self._ecu_id, self.monitor_lst, self._jitter_in)
        self._alert = TLSAlert(self.sim_env, self._record, self._ecu_id, self.monitor_lst, self._jitter_in)
        self._change_spec = TLSChangeCipherSpec(self.sim_env, self._record, self._ecu_id, self._handshake, self.monitor_lst, self._jitter_in)
        self._app_data = TLSApplicationTransmit(self.sim_env, self._record, self._ecu_id, self.monitor_lst, self._jitter_in)
        
        # interconnect
        self._handshake.change_spec = self._change_spec
        
    def _monitor_session_available(self, message_id, message, receiver):
        ''' monitors information if a session is 
            available
            
            Input:  message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
                    receiver     string        receiver of the message sent
            Output: -            
        '''
        monitor_tag = MonitorTags.CP_SESSION_AVAILABLE_SEND_MESSAGE
        now = self.sim_env.now
        uid = uuid.uuid4().hex
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self._ecu_id, now, receiver, message_id, message, len(message), message_id, uid))  
               
    def _session_available(self, sender_id, message_id):
        ''' true if a session with id sender_id and 
            message_id is already available.
        
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
            Output: -
        '''
        if sender_id in self._record.state:
            if message_id in self._record.state[sender_id]:
                if self._record.state[sender_id][message_id] == TLSState.AUTHENTICATED:
                    return True
        return False
        
    @property   
    def _jitter(self):
        return self._jitter_in
    
    @_jitter.setter   
    def _jitter(self, val):
        try:
            self._record._jitter = val
            self._record._rec_prep._jitter = val
            self._handshake._jitter = val
            self._alert._jitter = val
            self._change_spec._jitter = val
            self._app_data._jitter = val        
        except:
            pass
        self._jitter_in = val
            
    @property
    
    def ecu_id(self):
        return self._ecu_id
               
    @ecu_id.setter    
    
    def ecu_id(self, value):
        self._record.ecu_id = value
        self._handshake.ecu_id = value
        self._alert.ecu_id = value
        self._change_spec.ecu_id = value
        self._app_data.ecu_id = value        
        self._ecu_id = value          

    def monitor_update(self):
        ''' updates the monitor connected to this ecu
            
            Input:    -
            Output:   monitor_list    RefList    list of MonitorInputs
        '''
        items_1 = len(self.transp_lay.datalink_lay.controller.receive_buffer.items)
        items_2 = self.transp_lay.datalink_lay.transmit_buffer_size
        
        G().mon(self.monitor_lst, MonitorInput(items_1, MonitorTags.BT_ECU_RECEIVE_BUFFER, self._ecu_id, self.sim_env.now))
        G().mon(self.monitor_lst, MonitorInput(items_2, MonitorTags.BT_ECU_TRANSMIT_BUFFER, self._ecu_id, self.sim_env.now))
        
        self.monitor_lst.clear_on_access()  # on the next access the list will be cleared        
        return self.monitor_lst.get()

class TLSRecordLayer(object):
    
    def __init__(self, sim_env, transport_layer, ecu_id, monitor_lst=[], jitter=1):
        ''' Constructor
        
            Input:  sim_env                simpy.Environment        environment of this component    
                    transport_layer        AbstractTransportLayer   transport layer connected to this communication module
                    ecu_id                 string                   id of the ecu sending
                    communication_module   TeslaCommModule          communication module in which this class is
                    monitor_lst            RefList                  monitor list passed to monitor  
                    jitter                 float                    random value multiplied on each timeout
            Output: -        
        '''
        # passed parameters
        self.ecu_id = ecu_id
        self.sim_env = sim_env
        self._transp_lay = transport_layer
        self.monitor_lst = monitor_lst
        self._jitter = jitter
        
        # current state of transmission: between 2 ECUs (key per Stream)
        self.state = {}  # TLSState: ClientHello, ServerHello,... 
        self.mode = {}  # TLSMode: Client, Server
        
        # save keys for communication
        self.read_key = {}  # symmetric key used to decrypt messages
        self.read_mac_key = {}  # key for the MAC when receiving
        
        self.write_key = {}  # symmetric key used to encrypt messages
        self.write_mac_key = {}  # key for the MAC when sending
        
        # 4 States for security parameters
        self._w_pending_sec_params = {}  # TLSSecurityParameter for writing pending: depends on sending ECU and Stream ID (= SessionID)
        self._r_pending_sec_params = {}  # TLSSecurityParameter for reading pending: depends on sending ECU and Stream ID (= SessionID)      
          
        self._w_current_sec_params = {}  # current TLSSecurityParameter for writing: depends on sending ECU and Stream ID (= SessionID)
        self._r_current_sec_params = {}  # current TLSSecurityParameter for reading: depends on sending ECU and Stream ID (= SessionID)
        
        # Parameters                
        self._rec_prep = TLSRecordLayerPreparation(self.sim_env, self, monitor_lst=self.monitor_lst, jitter=jitter)
        self._init_project_parameters()
        self._init_calc_parameters()
              
    def send(self, sender_id, message_id, message, content_type, destination_id, stream_id):
        ''' sends the passed message from the sender with id sender_id to the 
            receiver with id destination_id
            
            Input:  sender_id        string             id of the sending ecu
                    message_id       integer            id of the message that is to be sent
                    content_type     TLSContentType     defines which protocol is sent (on top of record layer)
                    destination_id   string             id of the receiver ecu
                    stream_id        integer            id of the session
            Output: -        
        '''
        # create write state if not existing
        self._create_initial_sec_par_state(destination_id, stream_id)

        # use current write state for session
        self._set_sec_params_for_sending(destination_id, stream_id, message_id)
        
        # prepare message
        msg = yield self.sim_env.process(self._rec_prep.sender_data(message, content_type, self.TLSRL_PROTOCOL_VERSION, 0, sender_id, destination_id, stream_id))
        msg.dest_id = destination_id
         
        # send message
        yield self.sim_env.process(self._transp_lay.send_msg(sender_id, message_id, msg))
            
    def receive(self, msg_id, message_cipher, sender_id):
        ''' receives the message with id message_id from the ECU with
            id sender_id, decrypts it and validates it
            
            Input:  message_id       integer    id of the incoming message
                    message_cipher   object     depending on the ecu state this message can be an
                                                EncryptedMessage or a clear message
                    sender_id        string     id of the ECU that sent this message
            Output: clear_message    object     the clear received message
            
        '''
        
        # create read state if not existing
        stream_id = message_cipher[-2]
        self._create_initial_sec_par_state(sender_id, stream_id)
         
        # set current read state for session
        if (msg_id == can_registration.CAN_TLS_CHANGE_CIPHER_SPEC and self.mode[sender_id][stream_id] == TLSConnectionEnd.CLIENT):
            self._rec_prep.set_sec_params(self._r_pending_sec_params[sender_id][stream_id])  # for cipherspec client side use pending
        else: self._rec_prep.set_sec_params(self._r_current_sec_params[sender_id][stream_id])  # else the current one
        
        # try message extraction 
        try: clear_message = yield self.sim_env.process(self._rec_prep.receiver_data(message_cipher, sender_id, stream_id))
        except: clear_message = None

        # dummy-simpy
        if False:yield self.sim_env.timeout(0)        

        return clear_message
      

    def push_pending(self, sender_id, stream_id):
        ''' As the change cipher spec message was received the pending
            cipher suite will be set as current cipher suite 
            for the current session 
            
            Input:  sender_id    string     id of the ecu that sent the message
                    stream_id    integer    id of the session whose cipher suit will be 
                                            put from pending to current state
            Output:  -
        '''
        
        # push pending to current security parameters
        self._w_current_sec_params[sender_id][stream_id] = self._w_pending_sec_params[sender_id][stream_id]
        self._r_current_sec_params[sender_id][stream_id] = self._r_pending_sec_params[sender_id][stream_id]
        
        # pending state is empty again
        G().add_to_three_dict(self._w_pending_sec_params, sender_id, stream_id, TLSSecurityParameter())
        G().add_to_three_dict(self._r_pending_sec_params, sender_id, stream_id, TLSSecurityParameter())
        
        # calculate keys 
        self.set_keys_from_sec_par(self._w_current_sec_params[sender_id][stream_id], self._r_current_sec_params[sender_id][stream_id], sender_id, stream_id)
        
    
    def set_keys_from_sec_par(self, w_pars, r_pars, sender_id, stream_id):
        ''' given the security parameters the read and write keys for the communication
            with the ecu with id sender id over stream with stream_id are determined
            and set for the communication
        
            Input:  w_pars        TLSSecurityParameter    set that determines the write parameters of the communication
                    r_pars        TLSSecurityParameter    set that determines the read parameters of the communication  
                    sender_id     string                  id of the sending ECU
                    stream_id     integer                 id of the stream for which the keys are determined
            Output: -
        '''
        
        # Generate keyblock with appropriate length
        needed_block_len = w_pars.mac_key_length * 2 + w_pars.enc_key_length * 2 + w_pars.fixed_iv_length * 2        
        keyblock = self._generate_from_prf(needed_block_len, w_pars.prf_algorithm, w_pars.master_secret, w_pars.server_random, w_pars.client_random)
        
        # split keyblock to keys
        cl_write_mac_ky = keyblock[:w_pars.mac_key_length]
        ser_write_mac_ky = keyblock[w_pars.mac_key_length : 2 * w_pars.mac_key_length]
        cl_write_ky = keyblock[w_pars.mac_key_length * 2: 2 * w_pars.mac_key_length + w_pars.enc_key_length]
        ser_write_ky = keyblock[(2 * w_pars.mac_key_length + w_pars.enc_key_length): 2 * w_pars.mac_key_length + 2 * w_pars.enc_key_length]        
#         cl_iv = keyblock[(2 * w_pars.mac_key_length + 2 * w_pars.enc_key_length): 2 * w_pars.mac_key_length + 2 * w_pars.enc_key_length + w_pars.fixed_iv_length]
#         ser_iv = keyblock[(2 * w_pars.mac_key_length + 2 * w_pars.enc_key_length + w_pars.fixed_iv_length):]
        
        # set those write and read keys -> those then used for encryption
        if self.mode[sender_id][stream_id] == TLSConnectionEnd.SERVER:        
            # write keys    
            G().add_to_three_dict(self.write_key, sender_id, stream_id, ObjectMap().request_sym_key(sym_get_key(w_pars.bulk_cipher_algorithm, EnumTrafor().to_enum(w_pars.enc_key_length), w_pars.bulk_cipher_algorithm_option, ser_write_ky)))
            G().add_to_three_dict(self.write_mac_key, sender_id, stream_id, ObjectMap().request_mac_key(MACKey(w_pars.mac_algorithm, w_pars.mac_key_length, ser_write_mac_ky)))
        
            # read keys
            G().add_to_three_dict(self.read_key, sender_id, stream_id, ObjectMap().request_sym_key(sym_get_key(r_pars.bulk_cipher_algorithm, EnumTrafor().to_enum(r_pars.enc_key_length), r_pars.bulk_cipher_algorithm_option, cl_write_ky)))
            G().add_to_three_dict(self.read_mac_key, sender_id, stream_id, ObjectMap().request_mac_key(MACKey(r_pars.mac_algorithm, r_pars.mac_key_length, cl_write_mac_ky)))

        if self.mode[sender_id][stream_id] == TLSConnectionEnd.CLIENT:
            # write keys   
            G().add_to_three_dict(self.write_key, sender_id, stream_id, ObjectMap().request_sym_key(sym_get_key(w_pars.bulk_cipher_algorithm, EnumTrafor().to_enum(w_pars.enc_key_length), w_pars.bulk_cipher_algorithm_option, cl_write_ky)))
            G().add_to_three_dict(self.write_mac_key, sender_id, stream_id, ObjectMap().request_mac_key(MACKey(w_pars.mac_algorithm, w_pars.mac_key_length, cl_write_mac_ky)))
            
            # read keys
            G().add_to_three_dict(self.read_key, sender_id, stream_id, ObjectMap().request_sym_key(sym_get_key(r_pars.bulk_cipher_algorithm, EnumTrafor().to_enum(r_pars.enc_key_length), r_pars.bulk_cipher_algorithm_option, ser_write_ky)))  
            G().add_to_three_dict(self.read_mac_key, sender_id, stream_id, ObjectMap().request_mac_key(MACKey(r_pars.mac_algorithm, r_pars.mac_key_length, ser_write_mac_ky)))
    
    def _create_initial_sec_par_state(self, dest_id, stream_id):
        ''' if no initial security parameters were defined
            set them 
            
            Input:  dest_id      string     id of the communication partner with whom this ECU wants to communicate
                    stream_id    integer    id of the stream over which the partners communicate
            Output: -            
        '''
        
        # create new entry
        if dest_id not in self._w_current_sec_params: 
            self._w_current_sec_params[dest_id] = {}
            self._r_current_sec_params[dest_id] = {}
            self._w_pending_sec_params[dest_id] = {}
            self._r_pending_sec_params[dest_id] = {}  
                      
        # set empty TLS Security Parameters
        if stream_id not in self._w_current_sec_params[dest_id]:
            G().add_to_three_dict(self._w_current_sec_params, dest_id, stream_id, TLSSecurityParameter())
            G().add_to_three_dict(self._r_current_sec_params, dest_id, stream_id, TLSSecurityParameter())
            G().add_to_three_dict(self._w_pending_sec_params, dest_id, stream_id, TLSSecurityParameter())
            G().add_to_three_dict(self._r_pending_sec_params, dest_id, stream_id, TLSSecurityParameter())

    
    def _generate_from_prf(self, result_length, prf_algorithm, master_sec, server_ran, client_ran):
        ''' generates a byte sequence of length result_length depending on the given secrete and
            random number using the defined pseudo random number generator
            
            Input:  result_length        integer        length of the byte sequence that is created
                    prf_algorithm        function       method that is used for the generation args:  (byte, string, string)
        '''
        nr = 0        
        block = b""
        while len(block) < result_length:    
            nr += 1
            da_str = "key expansion " + str(nr)    
            block += prf_algorithm(master_sec, da_str, server_ran + client_ran)     
        return block[:result_length]
        
    
    def _init_calc_parameters(self):
        ''' initializes the project's parameters that are set in the 
            project.ini and timing.ini file
        
            Input:    -
            Output:   -
        '''
        
        #=======================================================================
        #     Record Layer
        #=======================================================================
        # Project 
        self.TLSRL_PROTOCOL_VERSION = proj.TLSRL_PROTOCOL_VERSION

        self.TLSR_COMPRESSION_ALGORITHM = proj.TLSR_COMPRESSION_ALGORITHM
        self.TLSR_COMPRESSED_SIZE = proj.TLSR_COMPRESSED_SIZE

        self.TLSR_BLOCKCIPHER_MAC_INPUT_SIZE = proj.TLSR_BLOCKCIPHER_MAC_INPUT_SIZE
        self.TLSR_BLOCKCIPHER_MAC_SIZE = proj.TLSR_BLOCKCIPHER_MAC_SIZE
        self.TLSR_BLOCKCIPHER_MAC_ALGORITHM = proj.TLSR_BLOCKCIPHER_MAC_ALGORITHM
        self.TLSR_BLOCKCIPHER_MAC_KEY_LEN = proj.TLSR_BLOCKCIPHER_MAC_KEY_LEN
        self.TLSR_DEC_BLOCKCIPHER_MAC_INPUT_SIZE = proj.TLSR_DEC_BLOCKCIPHER_MAC_INPUT_SIZE
        self.TLSR_DEC_BLOCKCIPHER_MAC_SIZE = proj.TLSR_DEC_BLOCKCIPHER_MAC_SIZE

        self.TLSR_BLOCKCIPHER_ENC_SIZE = proj.TLSR_BLOCKCIPHER_ENC_SIZE
        self.TLSR_BLOCKCIPHER_ENC_ALGORITHM = proj.TLSR_BLOCKCIPHER_ENC_ALGORITHM
        self.TLSR_BLOCKCIPHER_ENC_KEY_LEN = proj.TLSR_BLOCKCIPHER_ENC_KEY_LEN
        self.TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE = proj.TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE

        # Timing
        self.TLSR_COMPRESSION_TIME = time.TLSR_COMPRESSION_TIME
        self.TLSR_DECOMPRESSION_TIME = time.TLSR_DECOMPRESSION_TIME
        self.TLSR_MAC_BLOCKCIPHER_SEND_TIME = time.TLSR_MAC_BLOCKCIPHER_SEND_TIME
        self.TLSR_MAC_BLOCKCIPHER_REC_TIME = time.TLSR_MAC_BLOCKCIPHER_REC_TIME
        self.TLSR_BLOCKCIPHER_ENC_TIME = time.TLSR_BLOCKCIPHER_ENC_TIME
        self.TLSR_BLOCKCIPHER_DEC_TIME = time.TLSR_BLOCKCIPHER_DEC_TIME

        #=======================================================================
        #     TLS Handshake 
        #=======================================================================
        # Project 
        self.TLSH_CLIENT_HELLO_SEND_SIZE = proj.TLSH_CLIENT_HELLO_SEND_SIZE
        self.TLSH_CERT_VERIFY_CIPHER_SIZE = proj.TLSH_CERT_VERIFY_CIPHER_SIZE
        self.TLSH_CERT_VERIFY_CLEAR_SIZE = proj.TLSH_CERT_VERIFY_CLEAR_SIZE
        self.TLSH_SERV_CERT_ENC_ALG = proj.TLSH_SERV_CERT_ENC_ALG
        self.TLSH_SERV_CERT_ENC_KEY_LEN = proj.TLSH_SERV_CERT_ENC_KEY_LEN        
        self.TLSH_SERV_CERT_ENC_ALG_OPTION = proj.TLSH_SERV_CERT_ENC_ALG_OPTION
        self.TLSH_SERV_CERT_UNSIGNED_SIZE = proj.TLSH_SERV_CERT_UNSIGNED_SIZE
        self.TLSH_SERV_CERT_HASH_MECH = proj.TLSH_SERV_CERT_HASH_MECH
        self.TLSH_SERV_CERT_SIGNED_SIZE = proj.TLSH_SERV_CERT_SIGNED_SIZE
        self.TLSH_SERV_CERT_CA_LEN = proj.TLSH_SERV_CERT_CA_LEN
        
        self.TLSH_PRF_MASTER_SEC_GENERATION = proj.TLSH_PRF_MASTER_SEC_GENERATION
        
        self.TLSH_CLIENT_KEYEX_CIPHER_SIZE = proj.TLSH_CLIENT_KEYEX_CIPHER_SIZE
        self.TLSH_CLIENT_KEYEX_CLEAR_SIZE = proj.TLSH_CLIENT_KEYEX_CLEAR_SIZE
        self.TLSH_CLIENT_CERT_ENC_ALG = proj.TLSH_CLIENT_CERT_ENC_ALG
        self.TLSH_CLIENT_CERT_ENC_KEY_LEN = proj.TLSH_CLIENT_CERT_ENC_KEY_LEN
        self.TLSH_CLIENT_CERT_ENC_ALG_OPTION = proj.TLSH_CLIENT_CERT_ENC_ALG_OPTION
        self.TLSH_CLIENT_CERT_CA_LEN = proj.TLSH_CLIENT_CERT_CA_LEN
        self.TLSH_CLIENT_CERT_UNSIGNED_SIZE = proj.TLSH_CLIENT_CERT_UNSIGNED_SIZE
        self.TLSH_CLIENT_CERT_SIGNED_SIZE = proj.TLSH_CLIENT_CERT_SIGNED_SIZE
        self.TLSH_CLIENT_CERT_HASH_MECH = proj.TLSH_CLIENT_CERT_HASH_MECH        

        self.TLSH_SERVER_REC_FINISHED_HASH_SIZE = proj.TLSH_SERVER_REC_FINISHED_HASH_SIZE
        self.TLSH_SERVER_REC_FINISHED_CONTENT_SIZE = proj.TLSH_SERVER_REC_FINISHED_CONTENT_SIZE
        self.TLSH_FINISH_MESSAGE_HASH_ALGORITHM = proj.TLSH_FINISH_MESSAGE_HASH_ALGORITHM
        self.TLSH_SERVER_REC_FINISHED_PRF_ALG = proj.TLSH_SERVER_REC_FINISHED_PRF_ALG

        self.TLSH_CLIENT_REC_FINISHED_HASH_SIZE = proj.TLSH_CLIENT_REC_FINISHED_HASH_SIZE
        self.TLSH_CLIENT_REC_FINISHED_CONTENT_SIZE = proj.TLSH_CLIENT_REC_FINISHED_CONTENT_SIZE
        self.TLSH_CLIENT_REC_FINISHED_PRF_ALG = proj.TLSH_CLIENT_REC_FINISHED_PRF_ALG

        self.TLSH_SERVER_SEND_FINISHED_HASH_SIZE = proj.TLSH_SERVER_SEND_FINISHED_HASH_SIZE
        self.TLSH_SERVER_SEND_FINISHED_CONTENT_SIZE = proj.TLSH_SERVER_SEND_FINISHED_CONTENT_SIZE
        self.TLSH_SERVER_SEND_FINISHED_PRF_ALG = proj.TLSH_SERVER_SEND_FINISHED_PRF_ALG

        self.TLSH_CLIENT_SEND_FINISHED_HASH_SIZE = proj.TLSH_CLIENT_SEND_FINISHED_HASH_SIZE
        self.TLSH_CLIENT_SEND_FINISHED_CONTENT_SIZE = proj.TLSH_CLIENT_SEND_FINISHED_CONTENT_SIZE
        self.TLSH_CLIENT_SEND_FINISHED_PRF_ALG = proj.TLSH_CLIENT_SEND_FINISHED_PRF_ALG

        self.TLSH_CERT_SEND_SIZE = proj.TLSH_CERT_SEND_SIZE
        self.TLSH_CERT_REQUEST_SEND_SIZE = proj.TLSH_CERT_REQUEST_SEND_SIZE

        self.TLSH_SERVER_HELLO_SEND_SIZE = proj.TLSH_SERVER_HELLO_SEND_SIZE
        self.TLSH_SERVER_HELLO_DONE_SEND_SIZE = proj.TLSH_SERVER_HELLO_DONE_SEND_SIZE

        # Time 
        self.TLSH_DEC_CERT_VERIFY_TIME = time.TLSH_DEC_CERT_VERIFY_TIME
        self.TLSH_PRF_WORKING_TIME = time.TLSH_PRF_WORKING_TIME
        self.TLSH_DEC_CLIENT_KEYEX_TIME = time.TLSH_DEC_CLIENT_KEYEX_TIME
        self.TLSH_ENC_CLIENT_KEYEX_TIME = time.TLSH_ENC_CLIENT_KEYEX_TIME
        self.TLSH_SERVER_REC_FINISHED_HASH_TIME = time.TLSH_SERVER_REC_FINISHED_HASH_TIME
        self.TLSH_CLIENT_REC_FINISHED_HASH_TIME = time.TLSH_CLIENT_REC_FINISHED_HASH_TIME
        self.TLSH_SERV_HELLO_DONE_VERIFY_CERT_TIME = time.TLSH_SERV_HELLO_DONE_VERIFY_CERT_TIME

        self.TLSH_CERIFY_CLIENT_CERT_TIME = time.TLSH_CERIFY_CLIENT_CERT_TIME
        self.TLSH_SERVER_SEND_FINISHED_HASH_TIME = time.TLSH_SERVER_SEND_FINISHED_HASH_TIME
        self.TLSH_CLIENT_SEND_FINISHED_HASH_TIME = time.TLSH_CLIENT_SEND_FINISHED_HASH_TIME
        self.TLSH_ENC_CERT_VERIFY_TIME = time.TLSH_ENC_CERT_VERIFY_TIME

    
    def _init_project_parameters(self):
        ''' parameters of the project
            
            Input:    -
            Output:   -
        '''
        
        # ciphersuite
        self.available_ciphersuites = ObjectMap().request([TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, \
                        TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256])  # Ciphersuites supported by this Ecu
        self.negotiated_cipher_suite = {}
        self.negotiated_compression_method = {}
        
        # public and private keys for the certificate encryption
        self.server_cert_priv_keys = {}       
           
    
    def _set_sec_params_for_sending(self, dest_id, stream_id, message_id):
        ''' sets the current set to be used for encryption. Usually the current
            state is used. But on reception of the finished message the client
            will have to use the pending parameters to be able to decrypt the 
            message
             
            Input:  dest_id        string    id of the communication partner
                    stream_id      integer   id of the communication stream
                    message_id     integer   id of the message that was received on this call
            Output: - 
        '''
        # normal 
        self._rec_prep.set_sec_params(self._w_current_sec_params[dest_id][stream_id])
        
        # on client reception of finished message
        if (message_id == can_registration.CAN_TLS_FINISHED and self.mode[dest_id][stream_id] == TLSConnectionEnd.CLIENT):
            self._rec_prep.set_sec_params(self._w_pending_sec_params[dest_id][stream_id])   
           
class TLSRecordLayerPreparation(object):
    '''
    This class is used to help prepare messages that are sent via the record
    layer by offering a variety of helper functions
    '''
    def __init__(self, sim_env, record, current_sec_params=None, monitor_lst=[], jitter=1):
        ''' Constructor
        
            Input:  sim_env                simpy.Environment        environment of this component    
                    record                 TLSRecordLayer           record layer connected to the communication module
                    current_sec_params     TLSSecurityParameter     current security parameter set used for sending and receiving
                    monitor_lst            RefList                  monitor list passed to monitor  
                    jitter                 float                    random value multiplied on each timeout
            Output: -
        '''
        # passed parameters
        self._cur_sec_params = current_sec_params     
        self._record = record
        self._jitter = jitter        
        self.monitor_lst = monitor_lst
        self.sim_env = sim_env        
    
    def set_sec_params(self, sec_parameters):
        ''' sets the current security parameters that are used
            to send and receive messages on the record layer
        
            Input:    sec_parameters    TLSSecurityParameter     current security parameter set used for sending and receiving
            Output:   - 
        '''
        self._cur_sec_params = sec_parameters
    
    def receiver_data(self, message, sender_id, stream_id):
        ''' this method extracts the clear message from the 
            received message using the set defined in the 
            parameter self._cur_sec_params
        
            Input:  message            TLSCiphertext    received message that is to be decrypted
                    sender_id          string           id of the sender of this message
                    stream_id          integer          id of this message's stream
            Output: content_type       TLSContentType   enum defining which protocol was used (Handshake, Alert,...)
                    protocol_version   list             protocol version with format (x,x)
                    length             float            size of the cipher message
                    clear_message      object / SegData message that was received and decrypted 
        '''
        
        # information from TLSCiphertext
        content_type = message[0]
        protocol_version = message[1]
        length = message[2]
        clear_message = message[3].get()
        encrypted = message[5]
        
        if encrypted:
            # compressed size
            size_compressed = G().call_or_const(self._record.TLSR_COMPRESSED_SIZE, length, self._record.TLSR_COMPRESSION_ALGORITHM)             
            
            # decompression time
            decompression_time = time.call(self._record.TLSR_DECOMPRESSION_TIME, size_compressed, self._record.TLSR_COMPRESSION_ALGORITHM)
            decompression_time *= self._jitter
            
            # decryption time
            decryption_time = self._block_cipher_decrypted(size_compressed)
            
            # create verification mac             
            yield self.sim_env.timeout(decryption_time + decompression_time + self._create_mac_verification_receive(size_compressed))
                    
        # result
        return content_type, protocol_version, length, clear_message
    
    def sender_data(self, message, content_type, protocol_version, sequence_nr, sender_id, desination_id, stream_id):
        ''' this method prepares a clear message by encrypting and compressing it according to the 
            mechanisms defined in the parameter self._cur_sec_params which was negotiated between
            the sending/receiving parties
            
            Input:  message            SegData            message that needs to be prepared for sending
                    content_type       TLSContentType     enum defining which protocol was used (Handshake, Alert,...)
                    protocol_version   list               protocol version with format (x,x)
                    sequence_nr        integer            number of this message in the sequence of messages
                    sender_id          string             id of the sending ECU
                    desination_id      string             id of the target ECU for this message
                    stream_id          integer            id of the stream to which this message belongs
            Output: cipher_message     SegData            message that was prepared according to the defined security parameters        
        '''
           
        # plain text
        send_text = [content_type, protocol_version, len(message), message, stream_id, False]

        # compress text
        size_clear = len(message)
        size_compressed = G().call_or_const(self._record.TLSR_COMPRESSED_SIZE, size_clear, self._record.TLSR_COMPRESSION_ALGORITHM) 
        
        # determine time
        compression_time = time.call(self._record.TLSR_COMPRESSION_TIME, size_clear, self._record.TLSR_COMPRESSION_ALGORITHM) * self._jitter
            
        # use negotiated suite yet
        if self._cur_sec_params.master_secret != None: 
            # record layer protection - create fragment
            block_size = self._cur_sec_params.block_length
            padding_length = size_compressed % block_size
            
            # mac time       
            mac_time, maced_size = self._block_cipher_maced(size_compressed, padding_length)
            
            # encryption time               
            encryption_time, cipher_length = self._block_cipher_encrypted(size_compressed)                
            yield self.sim_env.timeout(encryption_time + mac_time + compression_time)
            length = 8 + cipher_length + maced_size + 5
            
            # encrypted True or not
            send_text[5] = True
            
        else:
            # encrypted True or not
            send_text[5] = False
            yield self.sim_env.timeout(compression_time)
            length = 8 + 5      
            
        # generate fragment
        fragment = send_text
                        
        # prepare message
        cipher_message = SegData(fragment, length)
        cipher_message.sender_id = sender_id
        
        # result
        return cipher_message
        
    def _block_cipher_decrypted(self, content_length):
        ''' this message calculates the time it takes to generate
            the cleartext from the given cipher with length content_length
            using the negotiated algorithm and key length
            
            Input:  content_length        float      length of the compressed message content
            Output: encryption_time       float      time it takes to encrypt a message with thee given content length  
                    cipher_length         float      size of the encrypted content
        '''
        # information
        algorithm = self._record.TLSR_BLOCKCIPHER_ENC_ALGORITHM
        algorithm_mode = self._record.TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE
        key_length = self._record.TLSR_BLOCKCIPHER_ENC_KEY_LEN
        
        # encrypted size
        cipher_length = G().call_or_const(self._record.TLSR_BLOCKCIPHER_ENC_SIZE, content_length, algorithm, key_length, 'ENCRYPTION')
        
        # decryption time
        decryption_time = G().call_or_const(self._record.TLSR_BLOCKCIPHER_DEC_TIME, cipher_length, algorithm, key_length, algorithm_mode)
        return decryption_time
        
    def _block_cipher_encrypted(self, content_length):
        ''' this message calculates the time it takes to generate
            the cipher from the given message with length content_length
            using the negotiated algorithm and key length
            
            Input:  content_length        float      length of the message content
            Output: encryption_time       float      time it takes to encrypt a message with thee given content length  
                    cipher_length         float      size of the encrypted content
        '''
        # information
        algorithm = self._record.TLSR_BLOCKCIPHER_ENC_ALGORITHM
        algorithm_mode = self._record.TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE
        key_length = self._record.TLSR_BLOCKCIPHER_ENC_KEY_LEN
        
        # encrypted size
        cipher_length = G().call_or_const(self._record.TLSR_BLOCKCIPHER_ENC_SIZE, content_length, algorithm, key_length, 'ENCRYPTION')
        
        # encryption time
        encryption_time = G().call_or_const(self._record.TLSR_BLOCKCIPHER_ENC_TIME, content_length, algorithm, key_length, algorithm_mode)
        return encryption_time, cipher_length
    
    def _block_cipher_maced(self, content_length, padding_length):
        ''' this message will calculate the MAC used in the generation of the
            GenericBlockCipher. This method returns the MAC size and the time
            it takes to generate the mac from a content with length 
            content_length
            
            Input:  content_length        float      length of the message content
                    padding_length        float      number of padded bytes to conform a multiple of the block size
            Output: mac_time              float      time it takes to generate a MAC from the given content length  
                    maced_size            float      size of the MAC generated            
        '''
        # parameter
        algorithm = self._record.TLSR_BLOCKCIPHER_MAC_ALGORITHM
        key_length = self._record.TLSR_BLOCKCIPHER_MAC_KEY_LEN
        
        # input size
        mac_input_size = G().call_or_const(self._record.TLSR_BLOCKCIPHER_MAC_INPUT_SIZE, content_length, padding_length)
        
        # mac size
        maced_size = G().call_or_const(self._record.TLSR_BLOCKCIPHER_MAC_SIZE, mac_input_size, algorithm, key_length, 'ENCRYPTION')
        
        # mac time
        mac_time = time.call(self._record.TLSR_MAC_BLOCKCIPHER_SEND_TIME, mac_input_size, algorithm, key_length) 
        mac_time *= self._jitter
        
        return mac_time, maced_size
        
    def _cipher_fragment(self, content, content_length, cipher_type, seq_nr, sender_id, target_id, stream_id):
        ''' generates a cipher fragment from the given content depending on the cipher type that was 
            defined. Depending on this parameter a GenericStreamCipher, a GenericBlockCipher or a 
            GenericAEADCipher is generated
            
            Input:  content             object                object that needs to be encrypted before transmission
                    content_length      float                 length of the message before encryption
                    cipher_type         TLSCipherType         cipher type with which the method shall be encrypted
                    seq_nr              integer               number indicating the message position in the message stream 
            Output: cipher_fragment     GenericStreamCipher/
                                        GenericBlockCipher/
                                        GenericAEADCipher     encrypted message depending on the selected cipher_type   
                    cipher_length       integer               length of the message after encryption 
        '''
        
        # no encryption
        fragment = None
        if cipher_type == None: return content, content_length
                
        # stream cipher (not implemented)
        if cipher_type == TLSCipherType.stream:
            cipher_fragment, cipher_length = self._generate_generic_stream_cipher(content, seq_nr, content_length)                    
            return cipher_fragment, cipher_length
            
        # AEAD cipher (not implemented)
        if cipher_type == TLSCipherType.aead:
            nonce_explicit = 0
            fragment = GenericAEADCipher(content, nonce_explicit)
            return fragment, self._cur_sec_params.record_iv_length + content_length
            
        # block Cipher (AES)
        if cipher_type == TLSCipherType.block:
            
            # block size
            block_size = self._cur_sec_params.block_length
            padding_length = content_length % block_size
            padding = "0"*padding_length    
            
            # no negotiated suite yet
            if self._cur_sec_params.master_secret == None: 
                iv, mac, cipher_fragment, cipher_length = 0, None, content, content_length
            
            # use negotiated suite
            else:
                # parameters
                iv, mac, cipher_fragment = self._extract_block_cipher_info(target_id, stream_id, content)
                         
                # mac time       
                mac_time, maced_size = self._block_cipher_maced(content_length, padding_length)
                
                # encryption time               
                encryption_time, cipher_length = self._block_cipher_encrypted(content_length)                
                yield self.sim_env.timeout(encryption_time + mac_time)
                
            # generate fragment
            fragment = GenericBlockCipher(iv, cipher_fragment, mac, padding, padding_length)

            return fragment, 8 + cipher_length + maced_size
                    
        return fragment, 0
    
    def _create_compressed_message_send(self, message, tls_plaintext, content_type, protocol_version):
        ''' compresses the tls_plaintext and returns the time this compression took as 
            well as the compressed message and its size
            
            Input:  message            SegData            message that needs to be prepared for sending
                    tls_plaintext      TLSPlaintext       clear message that was wrapped into a TLSPlaintext object 
                    content_type       TLSContentType     enum defining which protocol was used (Handshake, Alert,...)
                    protocol_version   list               protocol version with format (x,x)
            Output: 
        
        '''
        # determine size
        size_clear = len(message)
        size_compressed = G().call_or_const(self._record.TLSR_COMPRESSED_SIZE, size_clear, self._record.TLSR_COMPRESSION_ALGORITHM) 
        
        # determine time
        compression_time = time.call(self._record.TLSR_COMPRESSION_TIME, size_clear, self._record.TLSR_COMPRESSION_ALGORITHM) * self._jitter
        
        # compress message
        compressed_msg = compress(tls_plaintext, self._cur_sec_params.compression_algorithm)
        tls_compressed = TLSCompressed(content_type, protocol_version, size_compressed, compressed_msg)
    
        # result
        return tls_compressed, size_compressed, compression_time
    
    def _create_mac_verification_receive(self, size_compressed):
        ''' this message calculates the time needed to 
            create the verification hash for the receiving process
            of the record layer
            
            Input:    size_compressed    float    size of the compressed message that was received
            Output:   mac_time           float    time it takes to generate the verification hash
        '''
        # input size
        mac_input_size = G().call_or_const(self._record.TLSR_DEC_BLOCKCIPHER_MAC_INPUT_SIZE, size_compressed)
        
        # mac time
        mac_time = time.call(self._record.TLSR_MAC_BLOCKCIPHER_REC_TIME, mac_input_size, self._record.TLSR_BLOCKCIPHER_MAC_ALGORITHM, self._record.TLSR_BLOCKCIPHER_MAC_KEY_LEN) * self._jitter
        
        return mac_time
        
    def _decompress_receive(self, tls_compressed_msg):
        ''' this method decompresses the received text and 
            returns the size of the compressed message as well
            as the time to decompress it and the decompressed 
            message itself
            
            Input:  tls_compressed_msg   TLSCompressed   compressed message 
            Output: tls_plaintext        TLSPlaintext    plain text that will result after decompression   
                    decryption_time      float           time to decrypt the compressed message (resulting in the tls_plaintext)
                    size_compressed      float           size of the message compressed 
        
        '''
        # decompress
        tls_plaintext = decompress(tls_compressed_msg.fragment, self._cur_sec_params.compression_algorithm)   
        
        # clear size
        size_clear = len(tls_plaintext.fragment)            
        
        # compressed size
        size_compressed = G().call_or_const(self._record.TLSR_COMPRESSED_SIZE, size_clear, self._record.TLSR_COMPRESSION_ALGORITHM)             
        
        # decompression time
        decompression_time = time.call(self._record.TLSR_DECOMPRESSION_TIME, size_compressed, self._record.TLSR_COMPRESSION_ALGORITHM)
        decompression_time *= self._jitter
        
        # result
        return tls_plaintext, decompression_time, size_compressed
    
    def _extract_block_cipher_info(self, target_id, stream_id, content):
        ''' this method sets the initialization vector to the one negotiated 
            with the target_id for the session with stream id. Moreover it
            encrypts the mac with the defined keys as well as the cipher.
            
            Input:  target_id        string             id of the ECU that will receive the message
                    stream_id        integer            id of the session under which this message is sent
                    content          object             clear message that is to be encrypted
            Outpu:  iv               bytes              byte string that resembles the initialization vector
                    mac              MAC                mac calculated from the message content using the negotiated write key
                    cipher_fragment  EncryptedMessage   message that was encrypted using the negotiated write key 
        '''
        
        # initialization vector
        iv = 0  # self._record.write_iv[target_id][stream_id]
        
        # MAC
        mac = encryption_tools.mac(content, self._record.write_mac_key[target_id][stream_id])
        
        # encryption
        cipher_fragment = sym_encrypt(content, self._record.write_key[target_id][stream_id])    
    
        return iv, mac, cipher_fragment 
    
    def _generate_generic_stream_cipher(self, content, seq_nr, content_length):
        ''' creates a generic stream cipher from the given content using the 
            parameters defined in the current security parameters 
            self._cur_sec_params
            
            Input:  content             object                object that needs to be encrypted before transmission
                    seq_nr              integer               number indicating the message position in the message stream  
            Output: fragment            GenericStreamCipher   encrypted content  
                    fragment_length     float                 size of the message after encryption
            
            Note: Not implemented yet!
        '''
        mac_ctnt = str(seq_nr) + str(content.type) + str(content.prot_version) + str(content.length) + str(content.fragment)
        mac_key = MACKey(self._cur_sec_params.mac_algorithm, self._cur_sec_params.mac_key_length)  #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! USE REAL KEY
        mac = encryption_tools.mac(mac_ctnt, mac_key)
        fragment = GenericStreamCipher(content, mac)   
        fragment_length = self._cur_sec_params.mac_length + content_length  # not implemented 

        return fragment, fragment_length
                       
    def _uncipher_not_encrypted(self, tls_ciphertext):
        ''' returns the tlsplaintext when no encryption was used
            during the sending process
            
            Input:    tls_ciphertext    TLSCiphertext     received message cipher
            Output:   result            SegData/object    clear message received
        '''
        # decompress
        result = decompress(tls_ciphertext.fragment, self._cur_sec_params.compression_algorithm)            
        
        # decompress better
        if result == None:
            try: result = decompress(tls_ciphertext.fragment.fragment, self._cur_sec_params.compression_algorithm)
            except: return None
        
        # plaintext content
        result = result.fragment
        
        return result
            
class TLSHandshake(object):
    
    def __init__(self, env, tls_record, ecu_id, monitor_lst=[], jitter=1):
        ''' Constructor    
        
            Input:  sim_env         simpy.Environment        environment of this component
                    tls_record      TLSRecordLayer           record layer connected to this module
                    ecu_id          string                   id of the component holding this module
                    monitor_lst     RefList                  list used to update the monitor
                    jitter          float                    random value multiplied on each timeout
        
        '''
        # passed parameters
        self.sim_env = env        
        self.ecu_id = ecu_id        
        self.monitor_lst = monitor_lst        
        self._jitter = jitter
        self._record = tls_record
        
        # change cipher spec 
        self.change_spec = None
        
        # secret
        self.pre_master_secret = {}  # save it: receiverECU, associated Session ID (mapped from Stream ID)
        
    
    def _check_mode_states(self, node_id, rec_message_id, stream_id):
        ''' checks if the ECU is in the right mode and in the
            right state. According to the specification of TLS 
            only certain defined transitions between states are possible
            
            Input:  node_id            string        id of the communication partner ECU / target ECU
                    rec_message_id     integer       id of the message received (check if this message is allowed)
                    stream_id          integer       session id indicating the corresponding message stream 
            Output: bool               boolean       true if the requested transition initiated by the received message id
                                                     is valid                    
        '''
        try:
            # exception: ClientHello received
            if rec_message_id == can_registration.CAN_TLS_CLIENT_HELLO: 
                G().add_to_three_dict(self._record.mode, node_id, stream_id, TLSConnectionEnd.SERVER)
                G().add_to_three_dict(self._record.state, node_id, stream_id, TLSState.CLIENT_HELLO_RECEIVED)
                return True
            
            # current mode and state
            mode = self._record.mode[node_id][stream_id]
            state = self._record.state[node_id][stream_id]    
            
            # CLIENT SIDE
            if rec_message_id == can_registration.CAN_TLS_SERVER_HELLO:
                if state == TLSState.CLIENT_HELLO_SENT and mode == TLSConnectionEnd.CLIENT:
                    return True
                    
            if rec_message_id == can_registration.CAN_TLS_SERVER_CERTIFICATE:
                if state == TLSState.SERVER_HELLO_RECEIVED and mode == TLSConnectionEnd.CLIENT:
                    return True
                
            if rec_message_id == can_registration.CAN_TLS_SERVER_KEY_EXCHANGE:
                if state == TLSState.SERVER_CERTIFICATE_RECEIVED and mode == TLSConnectionEnd.CLIENT:
                    return True
                
            if rec_message_id == can_registration.CAN_TLS_CERTIFICATE_REQUEST:
                if (state == TLSState.SERVER_KEYEXCHANGE_RECEIVED or state == TLSState.SERVER_CERTIFICATE_RECEIVED) and mode == TLSConnectionEnd.CLIENT:
                    return True
                
            if rec_message_id == can_registration.CAN_TLS_SERVER_HELLO_DONE:
                if state == TLSState.CLIENT_CERTIFICATE_REQUEST_RECEIVED and mode == TLSConnectionEnd.CLIENT:
                    return True
                
            if rec_message_id == can_registration.CAN_TLS_CHANGE_CIPHER_SPEC:
                if state == TLSState.FINISHED_SENT and mode == TLSConnectionEnd.CLIENT:
                    return True
                
            if rec_message_id == can_registration.CAN_TLS_FINISHED:
                if state == TLSState.CHANGE_CIPHER_SPEC_RECEIVED and mode == TLSConnectionEnd.CLIENT:
                    return True
                
            # SERVER SIDE
            if rec_message_id == can_registration.CAN_TLS_CERTIFICATE:
                if state == TLSState.SERVER_HELLO_DONE_SENT and mode == TLSConnectionEnd.SERVER:
                    return True
                
            if rec_message_id == can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE:
                if state == TLSState.CLIENT_CERTIFICATE_RECEIVED and mode == TLSConnectionEnd.SERVER:
                    return True
                
            if rec_message_id == can_registration.CAN_TLS_CERTIFICATE_VERIFY:
                if state == TLSState.CLIENT_KEYEXCHANGE_RECEIVED and mode == TLSConnectionEnd.SERVER:
                    return True
                
            if rec_message_id == can_registration.CAN_TLS_CHANGE_CIPHER_SPEC:
                if state == TLSState.CERTIFICATE_VERIFY_RECEIVED and mode == TLSConnectionEnd.SERVER:
                    return True
                
            if rec_message_id == can_registration.CAN_TLS_FINISHED:
                if state == TLSState.CHANGE_CIPHER_SPEC_RECEIVED and mode == TLSConnectionEnd.SERVER:
                    return True            
            
        except:
            return False
        return False
    
    def process(self, sender_id, message_id, clear_message):
        ''' this method handles messages received by the communication module
            that use the handshake protocol
        
            Input:  sender_id        string     id of the sender that sent the message
                    message_id       integer    id of the received message
                    clear_message    SegData    clear message that was received from the record layer
            Output: -
        '''
        # extract stream ID
        try: stream_id = clear_message[3][-1]
        except: return            
        
        # check state of incoming
        if not self._check_mode_states(sender_id, message_id, stream_id): return 
        
        # respond
        # SERVER SIDE        
        if message_id == can_registration.CAN_TLS_CLIENT_HELLO:  # no state check!
            yield self.sim_env.process(self._handle_client_hello(clear_message, sender_id))             
            
        if message_id == can_registration.CAN_TLS_CERTIFICATE:            
            yield self.sim_env.process(self._handle_client_certificate(sender_id, clear_message))
            
        if message_id == can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE:
            yield self.sim_env.process(self._handle_client_keyexchange(sender_id, clear_message))
            
        if message_id == can_registration.CAN_TLS_CERTIFICATE_VERIFY:
            yield self.sim_env.process(self._handle_certificate_verify(sender_id, clear_message))
            
        if message_id == can_registration.CAN_TLS_FINISHED:
            yield self.sim_env.process(self._handle_finished(sender_id, clear_message))
            
        # -------------------------------------------------------------------------------------------- 
         
        # respond   
        # CLIENT SIDE
        if message_id == can_registration.CAN_TLS_SERVER_HELLO:
            yield self.sim_env.process(self._handle_server_hello(sender_id, clear_message))
            
        if message_id == can_registration.CAN_TLS_SERVER_CERTIFICATE:
            yield self.sim_env.process(self._handle_server_certificate(sender_id, clear_message))

        if message_id == can_registration.CAN_TLS_SERVER_KEY_EXCHANGE:
            yield self.sim_env.process(self._handle_server_key_exchange(sender_id, clear_message))

        if message_id == can_registration.CAN_TLS_CERTIFICATE_REQUEST:
            yield self.sim_env.process(self._handle_certificate_request(sender_id, clear_message))
            
        if message_id == can_registration.CAN_TLS_SERVER_HELLO_DONE:
            yield self.sim_env.process(self._handle_server_hello_done(sender_id, clear_message))

    
    def running(self, target_id, message_id): 
        ''' this method returns true if a handshake between the sender with id
            target_id is going on for the stream with id message_id
        
            Input:  target_id     string     id of the communication partner ECU
                    message_id    integer    id of the stream that has to be checked
            Output: -
        '''
        try:
            # only in AUTHENTICATED and NONE state handshake done
            if self._record.state[target_id][message_id] not in [TLSState.AUTHENTICATED, TLSState.NONE]:
                return True
            return False
        except:
            return False

    
    def send_client_hello(self, sender_id, stream_id, receiver_id):
        ''' send the client hello message to initialize a session for the 
            stream with id message_id and the communcation partner with
            ecu id receiver_id
            
            Input:  sender_id    string    id of the ECU sending the client hello command
                    stream_id   integer   id of the stream that requests to be initialized
                    receiver_id  string    id of the ECU that will have the session initalized with this ECU
            Output: - 
        '''
        
        # set states
        G().add_to_three_dict(self._record.state, receiver_id, stream_id, TLSState.CLIENT_HELLO_SENT)
        G().add_to_three_dict(self._record.mode, receiver_id, stream_id, TLSConnectionEnd.CLIENT)        
        
        # message content
        protocol_ver = self._record.TLSRL_PROTOCOL_VERSION
        cur_time = self.sim_env.now
        
        if "CLIENT_HELLO" in TLSCommModule.RANDOM_BYTES.keys():
            random_bytes = TLSCommModule.RANDOM_BYTES["CLIENT_HELLO"]
        else:
            random_bytes = os.urandom(28)
            TLSCommModule.RANDOM_BYTES["CLIENT_HELLO"] = random_bytes
        
        session_id = None  # No session available yet (no resumption intended)
        cipher_suite = self._record.available_ciphersuites
        compr_method = CompressionMethod.NULL
        extension_preset = []
        
        # clear Message
        clear_message = [protocol_ver, cur_time, random_bytes, session_id, cipher_suite, compr_method, extension_preset, receiver_id, stream_id]
        message_size = G().call_or_const(self._record.TLSH_CLIENT_HELLO_SEND_SIZE)
        msg = SegData(clear_message, message_size)
        
        # cache message
        self._log_sent_client_hello(receiver_id, clear_message, message_size, stream_id, msg.unique_id.hex)

        
        # send message        
        yield self.sim_env.process(self._record.send(sender_id, can_registration.CAN_TLS_CLIENT_HELLO, msg, TLSContentType.HANDSHAKE, receiver_id, stream_id))

    
    def _cache_server_hello(self, client_id, stream_id, clear_message, message_size, cipher_suite, compression_method):
        ''' this method caches the cipher suite and the compression method that were negotiated 
            on send server hello. Moreover the monitor object is informed
            
            Input:  client_id            string                id of the client
                    stream_id            integer               id of the session coresponding to this handshake
                    clear_message        list                  server hello message
                    message_size         float                 size of the server hello message
                    cipher_suite         TLSCipherSuite        cipher suite that was selected for this communication
                    compression_method   TLSCompressionMethod  compression method that was selected for this communication
            Output: -        
        '''
        # monitor
        now = self.sim_env.now
        uid = uuid.uuid4().hex
        message_id = can_registration.CAN_TLS_SERVER_HELLO
        monitor_tag = MonitorTags.CP_SEND_SERVER_HELLO       
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, client_id, message_id, clear_message, message_size, stream_id, uid)) 
        
        # cache cipher suite
        G().add_to_three_dict(self._record.negotiated_cipher_suite, client_id, stream_id, cipher_suite)
        
        # cache compression
        G().add_to_three_dict(self._record.negotiated_compression_method, client_id, stream_id, compression_method)
        
        # cache clear message
        clear_message = ObjectMap().request(clear_message)  # get wrapped message

        negotiated_suite = clear_message.get()[3]
        negotiated_compression = clear_message.get()[4]
        G().add_to_three_dict(self._record.negotiated_cipher_suite, client_id, stream_id, negotiated_suite)
        G().add_to_three_dict(self._record.negotiated_compression_method, client_id, stream_id, negotiated_compression)

      
    def _certificate_from_cipher_suite(self, suite, ca_length):
        ''' creates a certificate in dependance of the negotiated
            ciphersuite. i.e. the suite defines the algorithms 
            and hashing mechanisms used in the certificate
            
            Input:  suite                     TLSCipherSuite     suite that is to be used for the certificate creation
                    ca_length                 integer            number of CAs from the signing CA to the root CA
            Output: ecu_certificate           ECUCertificate     certificate generated for this ECU from a defined cipher suite
                    list_root_certificates    list               list of ECUCertificates that can be used to verify the passed certificate
                    private_key               AsymmetricKey      private key as counterpart to the public key of the ECUCertificate public key
            
        '''
        # unsupported suites
        if suite == TLSCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            logging.error("TLSCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA IS NOT SUPPORTED BY THE SYSTEM")
            return None, None
        
        elif suite == TLSCipherSuite.TLS_RSA_WITH_RC4_128_MD5:
            logging.error("TLSCipherSuite.TLS_RSA_WITH_RC4_128_MD5 IS NOT SUPPORTED BY THE SYSTEM")
            return None, None
        
        elif suite == TLSCipherSuite.TLS_RSA_WITH_RC4_128_SHA:
            logging.error("TLSCipherSuite.TLS_RSA_WITH_RC4_128_SHA IS NOT SUPPORTED BY THE SYSTEM")
            return None, None
        
        # supported suites
        elif suite == TLSCipherSuite.TLS_RSA_WITH_NULL_MD5:
            public_algorithm = AsymAuthMechEnum.RSA
            public_key_length = AuKeyLengthEnum.bit_1024
            hash_algorithm = HashMechEnum.MD5            
        
        elif suite == TLSCipherSuite.TLS_RSA_WITH_NULL_SHA:
            public_algorithm = AsymAuthMechEnum.RSA
            public_key_length = AuKeyLengthEnum.bit_1024
            hash_algorithm = HashMechEnum.SHA1
        
        elif suite == TLSCipherSuite.TLS_RSA_WITH_NULL_SHA256:
            public_algorithm = AsymAuthMechEnum.RSA
            public_key_length = AuKeyLengthEnum.bit_1024
            hash_algorithm = HashMechEnum.SHA256                    
            
        elif suite == TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
            public_algorithm = AsymAuthMechEnum.RSA
            public_key_length = AuKeyLengthEnum.bit_1024
            hash_algorithm = HashMechEnum.SHA1
        
        elif suite == TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
            public_algorithm = AsymAuthMechEnum.RSA
            public_key_length = AuKeyLengthEnum.bit_1024
            hash_algorithm = HashMechEnum.SHA256
        
        elif suite == TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
            public_algorithm = AsymAuthMechEnum.RSA
            public_key_length = AuKeyLengthEnum.bit_1024
            hash_algorithm = HashMechEnum.SHA1
        
        elif suite == TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
            public_algorithm = AsymAuthMechEnum.RSA
            public_key_length = AuKeyLengthEnum.bit_1024
            hash_algorithm = HashMechEnum.SHA256
                
        # ca length to enum     
        if ca_length == 1: ca = CAEnum.CA_L1            
        if ca_length == 2: ca = CAEnum.CA_L11            
        if ca_length == 3: ca = CAEnum.CA_L311

        # certificate from cipher suite
        hierarchy = CAHierarchy()
        hierarchy.rebuild_ca_information_default_algs(public_algorithm, public_key_length, hash_algorithm)
        manager = CertificateManager(hierarchy)
               
        # pull certificate
        if "Demo_Certificate" in TLSCommModule.CERT_REUSE.keys():
            ecu_certificate = TLSCommModule.CERT_REUSE["Demo_Certificate"]
            list_root_certificates = TLSCommModule.CERT_LIST_REUSE["Demo_Certificate"]
            private_key = TLSCommModule.PRIV_KEY_REUSE["Demo_Certificate"]
        else:
            ecu_certificate, list_root_certificates, private_key = manager.generate_valid_ecu_cert("Demo_Certificate", ca, 0, float('inf'), version=1.0)
            TLSCommModule.CERT_REUSE["Demo_Certificate"] = ecu_certificate 
            TLSCommModule.CERT_LIST_REUSE["Demo_Certificate"] = Wrapped(list_root_certificates)
            TLSCommModule.PRIV_KEY_REUSE["Demo_Certificate"] = private_key
             
        # result
        return ecu_certificate, TLSCommModule.CERT_LIST_REUSE["Demo_Certificate"] , private_key
    
     
    def _certificate_verify_encryption_time_size(self):
        ''' returns the time needed to encrypt the certificate verify message
            and the size after the encryption
            
            Input:  -
            Output: cipher_size        float        size of message after encryption
                    encryption_time    float        time to encrypt the message
        '''
        
        # size 
        size = self._record.TLSH_CERT_VERIFY_CLEAR_SIZE
        algorithm = self._record.TLSH_SERV_CERT_ENC_ALG
        algorithm_option = self._record.TLSH_SERV_CERT_ENC_ALG_OPTION
        key_length = self._record.TLSH_SERV_CERT_ENC_KEY_LEN
        
        # cipher size
        cipher_size = G().call_or_const(self._record.TLSH_CERT_VERIFY_CIPHER_SIZE, size, algorithm, key_length, 'ENCRYPTION')    
        
        # time 
        encryption_time = time.call(self._record.TLSH_ENC_CERT_VERIFY_TIME, algorithm, key_length, size, algorithm_option)
        
        return cipher_size, encryption_time
    
    
    def _check_certificate_verify_caches(self, sender_id, stream_id, clear_message):
        ''' this method checks the messages in the verify certificate message
            against the messages it sent and received so far from this communication
            partner. If they are equal True is returned
                       
            Input:  sender_id        string     id of the ECU sending the certificate verify message
                    stream_id        integer    stream id corresponding to this message
                    clear_message    list       clear certificate verify message that was received from the target ECU
            Output: bool             boolean    True if the messages received are equal to the cached once
        '''
        return True
    
       
    def _cipher_suite_supported(self, suites_incoming, client_id, stream_id):
        ''' True if any of the incoming suites do match the
            supported suites 
            
            Input:  suites_incoming     list        list of TLSCipherSuites that are supported by the communication
                                                    partner 
                    client_id           string      id of the client sending the message
                    stream_id           integer     corresponding stream
            Output: bool                boolean     true if any of the incoming suites is compatible with the ones supported
                                                    by this ecu
        '''
        for suite in suites_incoming:
            if suite in self._record.available_ciphersuites.get():
                return True    
              
        # if none supported log    
        monitor_tag = MonitorTags.CP_SEND_ALERT_NO_CIPHERSUITE
        now = self.sim_env.now
        message = "ERROR NO CIPHERSUITE"
        uid = uuid.uuid4().hex
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, client_id, 99191, message, 0, stream_id, uid))   
          
        return False
    
    
    def _client_certificate_validation_time(self, sender_id, clear_message, stream_id):
        ''' returns the time needed to verify the certificate that
            was received in the client certificate message
            
            Input:  sender_id        string     id of the ECU that sent the client certificate message
                    clear_message    list       clear client certificate message
                    stream_id        integer    id correasponding to this message stream
            Output: validation_time  float      time to validate the client certificate                      
        '''
        # monitor
        uuuid = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CERTIFICATE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, 0, stream_id, uuuid))
        
        # parameter
        hash_method = self._record.TLSH_CLIENT_CERT_HASH_MECH
        encryption_algorithm = self._record.TLSH_CLIENT_CERT_ENC_ALG
        encryption_algorithm_option = self._record.TLSH_CLIENT_CERT_ENC_ALG_OPTION
        key_length = self._record.TLSH_CLIENT_CERT_ENC_KEY_LEN
        ca_length = self._record.TLSH_CLIENT_CERT_CA_LEN
        unsigned_size = self._record.TLSH_CLIENT_CERT_UNSIGNED_SIZE
        
        # hashed size
        hash_size = EncryptionSize().output_size(self._record.TLSH_CLIENT_CERT_UNSIGNED_SIZE, hash_method, None, 'HASH')
        
        # signature size
        signed_size = G().call_or_const(self._record.TLSH_CLIENT_CERT_SIGNED_SIZE, hash_size, encryption_algorithm, key_length, 'SIGN')
        
        # validation time
        validation_time = time.call(self._record.TLSH_CERIFY_CLIENT_CERT_TIME, hash_method, encryption_algorithm, key_length, ca_length, unsigned_size, \
                                    signed_size, encryption_algorithm_option, self._record.TLSH_CERT_SEND_SIZE)
        
        # monitor after validation
        monitor_tag = MonitorTags.CP_CLIENT_CERTIFICATE_VALIDATED
        now = self.sim_env.now + validation_time
        message_id = can_registration.CAN_TLS_CERTIFICATE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, 0, stream_id, uuuid))
        
        return validation_time
    
    
    def _client_finish_hash_time(self):
        ''' this method calculates the hashing time needed to 
            hash the cached messages when the finished message 
            was received at client side
            
            Input:     -
            Output:    hashing_time    float    time to hash the cached messages
                       hashed_size     float    size of the hashed message            
        '''   
        # information
        content_size = self._record.TLSH_CLIENT_REC_FINISHED_CONTENT_SIZE
        algorithm = self._record.TLSH_FINISH_MESSAGE_HASH_ALGORITHM
        
        # size
        hashed_size = G().call_or_const(self._record.TLSH_CLIENT_REC_FINISHED_HASH_SIZE, content_size, algorithm, None, 'HASH')
        
        # time
        hashing_time = time.call(self._record.TLSH_CLIENT_REC_FINISHED_HASH_TIME, content_size, algorithm) * self._jitter
    
        return hashing_time, hashed_size
    
    
    def _client_finished_prf_time(self, sender_id, hashed, hashed_size, stream_id, uuuid, verification_hash):
        ''' this method calculates the time it takes to run the prf method
            that generates the comparison hash in the client finished message
            
            Input:  sender_id                string         id of the ECU that sent the message
                    hashed                   list           list of the clear verification message and the algorithm
                    hashed_size              float          size of the hashed message        
                    stream_id                integer        if of the stream corresponding to this finished message
                    uuuid                    hex            unique id corresponding to this message
                    verification_hash        bytes          byte string that is used to verify the received messages
            Output: prf_time                 float          time to generate the hash from the PRF
        '''
        # monitor
        monitor_tag = MonitorTags.CP_SERVER_FINISHED_HASHED_COMPARISON_HASH
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, hashed, hashed_size, stream_id, uuuid))
        
        # information
        master_secret = self._record._r_current_sec_params[sender_id][stream_id].master_secret
        
        # input size        
        input_size = len(master_secret) + len("client finished") + hashed_size
        
        # prf time
        prf_time = time.call(self._record.TLSH_PRF_WORKING_TIME, input_size, self._record.TLSH_CLIENT_REC_FINISHED_PRF_ALG)
        
        # monitor
        monitor_tag = MonitorTags.CP_SERVER_FINISHED_GENERATED_HASH_PRF
        now = self.sim_env.now + prf_time
        message_id = can_registration.CAN_TLS_FINISHED
        size = len(verification_hash)
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, verification_hash, size, stream_id, uuuid))
    
        return prf_time
    
    
    def _client_finished_verification_data(self, sender_id, stream_id):
        ''' this method generates the hash that is used for verification after
        the client received its finished message. This verification hash 
        is built from all messages that were sent and received during the
        stream with this id and the sender with this id.
        
        Input:  sender_id            string         id of the ECU that sent the message
                stream_id            integer        if of the stream corresponding to this finished message
        Output: verification_hash    bytes          byte string that is used to verify the received messages
                hashed               list           list of the clear verification message and the algorithm
        '''
        
        # determine PRF
        prf = self._prf_from_cipher_suite(TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)    
        
        # determine negotiated algorithm
        mac_algorithm = self._record._r_current_sec_params[sender_id][stream_id].mac_algorithm
        master_secret = self._record._r_current_sec_params[sender_id][stream_id].master_secret
        
        # gather cached messages        
        msg_clear = [0]
        
        # hash
        hashed = [str(msg_clear), mac_algorithm]  # hashed message dummy            
        verification_hash = prf(master_secret, "client finished", str(hashed))
        
        return verification_hash, hashed
        
    
    def _client_generate_premaster_secret(self, server_id, stream_id):
        ''' this method creates the premaster secret that can be inferred from
            previously exchanged messages
        
            Input:  server_id            string        id of the target server
                    stream_id            integer       corresponding stream id to this communication
            Output: pre_master_secret    bytes         string of bytes used to generate the master secret
                    uuu_id               hex           unique identifier corresponding to this message
        '''
        # information
        if "PRE_SEC" in TLSCommModule.RANDOM_BYTES.keys():
            random_nr = TLSCommModule.RANDOM_BYTES["PRE_SEC"]
        else:
            random_nr = os.urandom(46)
            TLSCommModule.RANDOM_BYTES["PRE_SEC"] = random_nr        
        
        protocol_ver = self._record.TLSRL_PROTOCOL_VERSION
        
        # pre master secret
        pre_master_secret = [random_nr, protocol_ver]        
        
        # cache secret
        G().add_to_three_dict(self.pre_master_secret, server_id, stream_id, pre_master_secret)
        
        # monitor
        uuu_id = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_INIT_SEND_CLIENT_KEYEXCHANGE
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, server_id, message_id, pre_master_secret, 0, stream_id, uuu_id))
    
        # result
        return pre_master_secret, uuu_id 
        
    
    def _client_hello_received_save_state(self, message, client_id):
        ''' this method saves the state after a client hello message
            was received and caches the message
            
            Input:  message        list        clear client hello message sent by client
                    client_id      string      id of client sending the client hello message
            Output: stream_id      integer     stream_id of this stream
            
        '''
        # extract stream
        stream_id = message[3][-1]
                
        # save state and mode
        G().add_to_three_dict(self._record.state, client_id, stream_id, TLSState.CLIENT_HELLO_RECEIVED)
        G().add_to_three_dict(self._record.mode, client_id, stream_id, TLSConnectionEnd.SERVER)
    
        # monitor
        monitor_tag = MonitorTags.CP_RECEIVE_CLIENT_HELLO
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CLIENT_HELLO
        uid = uuid.uuid4().hex
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, client_id, message_id, message, 0, stream_id, uid))  
        
        return stream_id
    
    
    def _client_key_exchange_decryption_time(self, sender_id, exchange_message, stream_id, uid, clear_message):
        ''' this message returns the time needed to decrypt the client
            key exchange message
            
            Input:  sender_id            string      id of the ECU that sent the key exchange message
                    exchange_message     list        clear key exchange message
                    stream_di            integer     id of the corresponding message stream
                    uid                  hex         unique id of this message
                    clear_message        list        clear key exchange message
            Output: decryption_time      flaot       time to decrypt the key exchange message  
        '''
        
        # parameter
        algorithm = self._record.TLSH_CLIENT_CERT_ENC_ALG
        algorithm_option = self._record.TLSH_CLIENT_CERT_ENC_ALG_OPTION
        key_length = self._record.TLSH_CLIENT_CERT_ENC_KEY_LEN
        clear_size = self._record.TLSH_CLIENT_KEYEX_CLEAR_SIZE
        
        # encrypted size        
        cipher_size = G().call_or_const(self._record.TLSH_CLIENT_KEYEX_CIPHER_SIZE, clear_size, algorithm, key_length, 'ENCRYPTION')     
        
        # decryption time
        decryption_time = time.call(self._record.TLSH_DEC_CLIENT_KEYEX_TIME, algorithm, key_length, cipher_size, algorithm_option)
        
        # monitor 
        monitor_tag = MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, exchange_message[3][0], cipher_size, stream_id, uid))
        
        # monitor after decryption
        monitor_tag = MonitorTags.CP_DECRYPTED_CLIENT_KEYEXCHANGE
        now = self.sim_env.now + decryption_time
        message_id = can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE
        size = self._record.TLSH_CLIENT_KEYEX_CLEAR_SIZE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, size, stream_id, uid))
        
        return decryption_time
    
        
    def _client_key_exchange_encryption_time(self, server_id , stream_id, pre_master_secret, uuu_id):
        ''' this method returns the time needed to encrypt the key exchange message and the size of
            the message after encryption
        
            Input:  server_id            string        id of the target server
                    stream_id            integer       corresponding stream id to this communication
                    pre_master_secret    bytes         string of bytes used to generate the master secret
                    uuu_id               hex           unique identifier corresponding to this message
            Output: encryption_time      float         time to encrypt the key exchange message
                    cipher_size          float         size of the encrypted key exchange message
        '''
        # information
        size = self._record.TLSH_CLIENT_KEYEX_CLEAR_SIZE
        algorithm = self._record.TLSH_CLIENT_CERT_ENC_ALG
        algorithm_option = self._record.TLSH_CLIENT_CERT_ENC_ALG_OPTION
        key_length = self._record.TLSH_CLIENT_CERT_ENC_KEY_LEN
        
        # cipher size
        cipher_size = G().call_or_const(self._record.TLSH_CLIENT_KEYEX_CIPHER_SIZE, size, algorithm, key_length, 'ENCRYPTION')     
        
        # encryption time
        encryption_time = time.call(self._record.TLSH_ENC_CLIENT_KEYEX_TIME, algorithm, key_length, size, algorithm_option)
        
        # monitor
        monitor_tag = MonitorTags.CP_ENCRYPTED_CLIENT_KEYEXCHANGE
        now = self.sim_env.now + encryption_time
        message_id = can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, server_id, message_id, pre_master_secret, cipher_size, stream_id, uuu_id))
        
        # result
        return encryption_time, cipher_size
    
    
    def _client_key_exchange_prf_time(self, server_id, stream_id, client_random, server_random, master_secret, uuu_id):
        ''' returns the time needed to run the PRF function during master secret creation 
            at the client side
            
            Input:  server_id        string         id of the target server
                    stream_id        integer        corresponding stream id to this communication
                    client_random    string         random string of client
                    server_random    string         random string of server
                    master_secret    bytes          string of bytes defining the master secret
                    uuu_id           hex            unique identifier corresponding to this message
            Output: prf_time         float          time to run the prf function  
        '''
        # information 
        pre_master_secret_1 = self.pre_master_secret[server_id][stream_id][0]
        pre_master_secret_2 = self.pre_master_secret[server_id][stream_id][1]
        
        # input size
        input_size = len(client_random) + len(server_random) + 11 + len(pre_master_secret_1) + len(pre_master_secret_2)

        # prf time
        prf_time = time.call(self._record.TLSH_PRF_WORKING_TIME, input_size, self._record.TLSH_PRF_MASTER_SEC_GENERATION)
        
        # monitor
        size = len(master_secret)
        now = self.sim_env.now + prf_time
        monitor_tag = MonitorTags.CP_GENERATED_MASTERSEC_CLIENT_KEYEXCHANGE        
        message_id = can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE        
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, server_id, message_id, master_secret, size, stream_id, uuu_id))
    
        # result
        return prf_time
    
    
    def _client_key_exchange_set_pending_configuration(self, server_id, stream_id, pre_master_secret, uuu_id):
        ''' after the client key exchange message was received the pending
            configuration has to be set in the record layer
            
            Input:  server_id        string        id of the target server
                    stream_id        integer       corresponding stream id to this communication
                    pre_master_secret    bytes         string of bytes used to generate the master secret
                    uuu_id               hex           unique identifier corresponding to this message
            Output: -
        '''
                
        
        # client and server random
        client_random = TLSCommModule.RANDOM_BYTES["CLIENT_HELLO"]
        server_random = TLSCommModule.RANDOM_BYTES["SERVER_HELLO"]
        master_secret = self._generate_master_secret(TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, pre_master_secret, client_random, server_random)
        
        # prf time (master secret generation)
        yield self.sim_env.timeout(self._client_key_exchange_prf_time(server_id, stream_id, client_random, server_random, master_secret, uuu_id))
        
        # information
        cipher_suite = TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
        compression_method = CompressionMethod.NULL
        prf = self._dummy_prf
        current_master_secret = self._record._w_current_sec_params[server_id][stream_id].master_secret

        # clear read pending
        G().add_to_three_dict(self._record._r_pending_sec_params, server_id, stream_id, TLSSecurityParameter())
        
        # set read pending
        self._record._r_pending_sec_params[server_id][stream_id].from_cipher_suite(TLSConnectionEnd.CLIENT, cipher_suite, compression_method, \
                                                                                   master_secret, server_random, client_random, prf)
        
        # clear write pending
        G().add_to_three_dict(self._record._w_pending_sec_params, server_id, stream_id, TLSSecurityParameter())
        
        # set write pending
        self._record._w_pending_sec_params[server_id][stream_id].from_cipher_suite(TLSConnectionEnd.CLIENT, cipher_suite, compression_method, \
                                                                                   master_secret, server_random, client_random, prf)   
        
        # current master secret
        if current_master_secret == None:
            self._record.set_keys_from_sec_par(self._record._w_pending_sec_params[server_id][stream_id], \
                                               self._record._r_pending_sec_params[server_id][stream_id], server_id, stream_id)
    
      
    def _create_client_finished_clear_message(self, sender_id, stream_id):
        ''' create a message containing all messages cached for the communication
            of this ECU with the ECU with id sender id over the stream with stream_id.
            Moreover the PRF for the communication is extracted
            
            Input:  sender_id       string         id of the communication partner who will receive the server 
                                                   finished message
                    stream_id       integer        id of the current communication stream
            Output: clear_message   list       all messages sent and received so far over this stream
                    prf             function   method that was negotiated to be used for randomization
                    uuuid           hex        unique identifier corresponding to this message
        '''
        # uid
        uuuid = uuid.uuid4().hex
           
        # cached messages
        clear_message = [0]
        
        # PRF for communication
        prf = self._prf_from_cipher_suite(TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA) 
        
        # monitor
        monitor_tag = MonitorTags.CP_INIT_CLIENT_FINISHED
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        size = self._record.TLSH_CLIENT_SEND_FINISHED_CONTENT_SIZE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, size, stream_id, uuuid))
             
        # result            
        return clear_message, prf, uuuid
    
    
    def _create_server_finished_clear_message(self, sender_id, stream_id):
        ''' this method creates a message consisting of all messages send and received
            so far during the communication with the sender sender_id over the 
            stream with id stream_id
        
            Input:  sender_id        string     id of the communication partner
                    stream_id        integer    id of the stream id over which the ecus communicate
            Output: clear_message    list       all messages sent and received so far over this stream
                    prf              function   method that was negotiated to be used for randomization
                    uuuid            hex        unique identifier corresponding to this message
        '''
        
        # create message
        clear_message = [ 0]
        
        # PRF
        prf = self._prf_from_cipher_suite(self._record.negotiated_cipher_suite[sender_id][stream_id])            
        
        # monitor
        uuuid = uuid.uuid4().hex       
        monitor_tag = MonitorTags.CP_INIT_SERVER_FINISHED
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        size = self._record.TLSH_SERVER_SEND_FINISHED_CONTENT_SIZE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, size, stream_id, uuuid))
        
        return clear_message, prf, uuuid
    
    
    def _decrypt_certificate_verify(self, encrypted_message, private_key, stream_id, uuuid, sender_id):
        ''' this method decrypts the certificate verify message using the 
            private key of the server certificate that was sent earlier to
            the client
            
            Input:  encrypted_message    EncryptedMessage       message that was received 
                    private key          AsymmetricKey          private key of the server certificate 
                    stream_id            integer                id of the stream corresponding to this session
                    uuuid                hex                    unique id corresponding to the received message
                    sender_id            string                 id of the client sending the certificate verify message
            Output: clear_message        list                   decrypted certificate verify message
                    decryption_time      float                  time needed for the decryption of the certificate verify message
            
        '''
        # information
        algorithm = self._record.TLSH_SERV_CERT_ENC_ALG
        algorithm_option = self._record.TLSH_SERV_CERT_ENC_ALG_OPTION
        key_length = self._record.TLSH_SERV_CERT_ENC_KEY_LEN
        
        # decrypt
        clear_message = encryption_tools.asy_decrypt(encrypted_message, private_key, self.sim_env.now)
        clear_size = self._record.TLSH_CERT_VERIFY_CLEAR_SIZE
        
        # size
        cipher_size = G().call_or_const(self._record.TLSH_CERT_VERIFY_CIPHER_SIZE, clear_size, algorithm, key_length, 'ENCRYPTION')     
        
        # time
        decryption_time = time.call(self._record.TLSH_DEC_CERT_VERIFY_TIME, algorithm, key_length, cipher_size, algorithm_option)
        
        # monitor
        monitor_tag = MonitorTags.CP_RECEIVE_CERTIFICATE_VERIFY
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CERTIFICATE_VERIFY
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, cipher_size, stream_id, uuuid))
        
        # monitor after decryption
        monitor_tag = MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY
        now = self.sim_env.now + decryption_time
        message_id = can_registration.CAN_TLS_CERTIFICATE_VERIFY
        size = self._record.TLSH_CERT_VERIFY_CLEAR_SIZE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, size, stream_id, uuuid))
        
        # result
        return clear_message, decryption_time
    
    
    def _dummy_prf(self, pre_master, str_input, cl_ran_pl_serv_ran):
        ''' this pseudo random function simply hashes the incoming components
            to generate a master secrete of length 48
            
            Input:  pre_master            string    pre master secret 
                    str_input             string    any input string
                    cl_ran_pl_serv_ran    string    concatenation of client's and server's random numbers
            Output: master_secret         string    mastersecret of length 48 bytes
        '''
        
        # dump: hash everything
        hash_1 = md5(bytes(str(pre_master), 'utf-8')).digest()
        hash_2 = md5(bytes(str(str_input), 'utf-8')).digest()
        hash_3 = md5(bytes(str(cl_ran_pl_serv_ran), 'utf-8')).digest()
        
        master_secret = hash_1 + hash_2 + hash_3
        
        return master_secret
    
    
    def _generate_certificate_verify_clear(self, server_id, stream_id, uid):
        ''' this method returns the cached messages as a list that were received
            until the certificate verify message
            
            Input:  server_id        string            id of the target server
                    stream_id        integer           corresponding stream id to this communication
                    uid              hex               unique id corresponding to this message 
            Output: clear_message    list              list of all send and received messages with this stream_id
                    public_key       AsymmetricKey     public key of the server certificate 
        '''

        # concatenate
        clear_message = [0]         
        
        # public key
        public_key = TLSCommModule.CERT_REUSE["Demo_Certificate"].pub_key_user
        
        # monitor
        monitor_tag = MonitorTags.CP_INIT_SEND_CERTIFICATE_VERIFY
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE
        size = self._record.TLSH_CERT_VERIFY_CLEAR_SIZE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, server_id, message_id, clear_message, size, stream_id, uid))
        
        # results
        return clear_message, public_key
    
    
    def _generate_master_certificate_verify(self, sender_id, stream_id):
        ''' after the certificate verify message was received and validated
            this method generates the master secret from the negotiated
            premaster secret the client random number and the server random
            number
            
            Input:  sender_id        string     id of the ECU sending the certificate verify message
                    stream_id        integer    stream id corresponding to this message
            Output: master_secret    string     master secret generated from negotiated
                    prf_time         float      time it takes to generate the master secret
                    client_random    string     random string of client
                    server_random    string     random string of server                    
        '''
        # determine information
        pre_master_secret = self.pre_master_secret[sender_id][stream_id]
        cipher_suite = self._record.negotiated_cipher_suite[sender_id][stream_id]
        client_random = TLSCommModule.RANDOM_BYTES["CLIENT_HELLO"]
        server_random = TLSCommModule.RANDOM_BYTES["SERVER_HELLO"]
        
        # generate secret
        master_secret = self._generate_master_secret(cipher_suite, pre_master_secret, client_random, server_random)
    
        # size
        input_size = len(client_random) + len(server_random) + 11 + len(pre_master_secret[0]) + len(pre_master_secret[1])        
        
        # time for generation
        prf_time = time.call(self._record.TLSH_PRF_WORKING_TIME, input_size, self._record.TLSH_PRF_MASTER_SEC_GENERATION)
            
    
        return master_secret, prf_time, client_random, server_random
    
    
    def _generate_master_secret(self, cipher_suite, pre_master_secret, client_random, server_random):
        ''' this method creates the master secret from the negotiated pre master secret using 
            the prf that results from the negotiated cipher suite
            
            Input:  cipher_suite        TLSCipherSuite        cipher suite that was negotiated during handshake
                    pre_master_secret   string                pre master secret that was negotiated
                    client_random       string                random number generated by the client
                    server_random       string                random number generated by the server
            Output: master_secret       string                master secret of length 48 bytes                 
        '''
        
        # Pseudorandom function depends on cipher suite: 
        prf = self._prf_from_cipher_suite(cipher_suite)    
        master_secret = prf(pre_master_secret, "master secret", client_random + server_random)        
        return master_secret
    
    
    def _generate_message_components_cert_request(self):
        ''' generates the individual message components for the 
            certificate request message
            
            Input:    -
            Output: certificate_type       list        list of accepted TLSCertificateType s
                    sign_hash_algorithms    list        list of allowed Sign/Hash combinations 
                    accepted_cas_list      list        list of accepted CAs
        '''
        # certificate type
        certificate_type = []
        certificate_type.append(TLSCertificateType.ECC_SIGN)
        certificate_type.append(TLSCertificateType.RSA_SIGN)

        # sign and hash algorithm
        sign_hash_algorithms = []
        sign_hash_algorithms.append(SignatureAndHashAlgorithm(HashMechEnum.MD5, AsymAuthMechEnum.ECC))
        sign_hash_algorithms.append(SignatureAndHashAlgorithm(HashMechEnum.MD5, AsymAuthMechEnum.RSA))
        
        # cas accepted
        accepted_cas_list = []
        accepted_cas_list += [CAEnum.CA_L1, CAEnum.CA_L2, CAEnum.CA_L3]
        accepted_cas_list += [CAEnum.CA_L11, CAEnum.CA_L12, CAEnum.CA_L13]
        accepted_cas_list += [CAEnum.CA_L21, CAEnum.CA_L22, CAEnum.CA_L23]
        accepted_cas_list += [CAEnum.CA_L31, CAEnum.CA_L32, CAEnum.CA_L33 ]
        accepted_cas_list += [CAEnum.CA_L311, CAEnum.CA_L312, CAEnum.CA_L313]
        
        return certificate_type, sign_hash_algorithms, accepted_cas_list
    
        
    def _handle_certificate_request(self, sender_id, clear_message):
        ''' this method handles the certificate request message by simply
            caching it
            
            Input:  sender_id            string    id of the ecu sending the certificate request message
                    clear_message        list      certificate request message
            Output: -        
        '''        
        
        # set state
        stream_id = clear_message[3][-1]        
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.CLIENT_CERTIFICATE_REQUEST_RECEIVED)
#         print("%s Handle certificate request" % stream_id)
        
        # monitor
        monitor_tag = MonitorTags.CP_RECEIVE_CERTIFICATE_REQUEST
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CERTIFICATE_REQUEST
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, 0, stream_id, uuid.uuid4().hex))
               
        # dummy
        if False: yield self.sim_env.timeout(0)
    
    
    def _handle_certificate_verify(self, sender_id, message):
        ''' this method handles a certificate verify message by decrypting the 
            message using its certificates private key
            
            Input:  sender_id    string    id from the ECU that sent the certificate verify message
                    message      list      certificate verify message
            Output: -  
        '''        
                
        # extract message
        stream_id, encrypted_message = message[3][-1], message[3][0]  
#         print("%s Handle certificate Verify" % stream_id)  
        uuuid = uuid.uuid4().hex
        private_key = self._record.server_cert_priv_keys[sender_id][stream_id]        
        
        # decrypt message
        clear_message, dec_time = self._decrypt_certificate_verify(encrypted_message, private_key, stream_id, uuuid, sender_id)        
        yield self.sim_env.timeout(dec_time)

        # set state        
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.CERTIFICATE_VERIFY_RECEIVED)
        
        # check cached against received
        same = self._check_certificate_verify_caches(sender_id, stream_id, clear_message)
#         print("Verify certificate %s" % stream_id)
        if same:
            # generate master secret
            master_secret, prf_time, client_random, server_random = self._generate_master_certificate_verify(sender_id, stream_id)            
            yield self.sim_env.timeout(prf_time)
            
            # set record layer spec
            self._set_record_layer_spec_certificate_verify(sender_id, stream_id, master_secret, server_random, client_random, uuuid)
    
        
    def _handle_client_certificate(self, sender_id, clear_message):
        ''' handles the client certificate that was received by checking
            its validity and caching it
            
            Input:  sender_id        string    id of the ECU that sent the client certificate message
                    clear_message    list      clear client certificate message
            Output: -
        '''
        # set state
        stream_id = clear_message[3][-1]
#         print("%s Handle client certificate" % stream_id)
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.CLIENT_CERTIFICATE_RECEIVED)        
        
        # extract message
        certificate = clear_message[3][0]
        root_certificate_list = clear_message[3][1].get()
        
        # validate client certificate       
        if not certificate_trustworthy(certificate, root_certificate_list, self.sim_env.now):
            G().add_to_three_dict(self._record.state, sender_id, stream_id, None); return
        
        # validate client certificate
        validation_time = self._client_certificate_validation_time(sender_id, clear_message, stream_id)        
        yield self.sim_env.timeout(validation_time)        
        
        # dummy
        if False: yield self.sim_env.timeout(0)
        
    
    def _handle_client_hello(self, message, client_id):
        ''' this method handles the client hello message received. It checks the 
            supported cipher suites against the received once and answers with the 
            respective server messages
        
            Input:  message        list        clear client hello message sent by client
                    client_id      string      id of client sending the client hello message
            Output: -  
        '''
        
        # set state and logging
        stream_id = self._client_hello_received_save_state(message, client_id)
#         print("%s Handle client hello" % stream_id)
        
        # Check if any of the received cipher suites supported, else alert
        if not self._cipher_suite_supported(message[3][4].get(), client_id, stream_id):            
            yield self.sim_env.process(self._send_alert_no_cipher_suite())
         
        # send server hello  
        yield self.sim_env.process(self._send_server_hello(message, client_id, stream_id)) 
        
        # send server certificate
        yield self.sim_env.process(self._send_server_certificate(client_id, stream_id)) 
         
        # send key exchange    
        yield self.sim_env.process(self._send_server_key_exchange(client_id, stream_id))
 
        # send certificate request
        yield self.sim_env.process(self._send_certificate_request(client_id, stream_id))
        
        # send server hello done 
        yield self.sim_env.process(self._send_server_hello_done(client_id, stream_id))
    
    
    def _handle_client_keyexchange(self, sender_id, exchange_message):
        ''' this method handles the received client key exchange message. The message
            is decrypted and cached
            
            Input:  sender_id            string    id of the ecu sending the key exchange message
                    exchange_message     list      clear key exchange message
            Output: -
        '''
        
        
        # set state
        stream_id, uid = exchange_message[3][-1], uuid.uuid4().hex
#         print("%s Handle client key exchange" % stream_id)
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.CLIENT_KEYEXCHANGE_RECEIVED)

        # decrypt premaster secret: use private key of certificate
        private_key = self._record.server_cert_priv_keys[sender_id][stream_id]
        clear_message = encryption_tools.asy_decrypt(exchange_message[3][0], private_key, self.sim_env.now)
                
        # decryption time
        decryption_time = self._client_key_exchange_decryption_time(sender_id, exchange_message, stream_id, uid, clear_message)
        yield self.sim_env.timeout(decryption_time)
        
        # cache message
        G().add_to_three_dict(self.pre_master_secret, sender_id, stream_id, clear_message)
    
    
    def _handle_finished(self, sender_id, message):
        ''' this method receives the server and the client finished message and handles
            it accordingly. If the server received a finished message it looks at all
            cached messages for this stream_id and checks if it is equal to the received
            messages in the finished message. If that is the case it responds with 
            a ChangeCipherSpec message followed by a Finished message. 
            If the client received a finished message it looks at all
            cached messages for this stream_id and checks if it is equal to the received
            messages in the finished message. Once this condition is fulfilled this 
            stream is granted and the messages can be exchanged using the application layer
            with security offered by the record layer protection mechanism.
            
            Input:  sender_id        string        id of the ECU that sent the message
                    message          object        finished message that needs to be processed
            Output: -        
        '''
                
        # set state
        stream_id = message[3][-1]
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.FINISHED_RECEIVED)
        message = message[3][0]    
        
        # server finished
        if self._record.mode[sender_id][stream_id] == TLSConnectionEnd.SERVER:   

            # set server state
            uuuid, received_hash = self._set_server_finished_message_state(sender_id, stream_id, message), message
            
            # create comparables
            verification_hash, hashed = self._server_finished_verification_data(sender_id, stream_id)            
            
            # hash time
            time_hash, hashed_size = self._server_finish_hash_time()            
            yield self.sim_env.timeout(time_hash)
            
            # prf time
            yield self.sim_env.timeout(self._server_finished_prf_time(sender_id, hashed, hashed_size, stream_id, uuuid, verification_hash))
           
            # compare
            if received_hash == verification_hash:
                TLSCommModule.CNT += 1
#                 print("%s: First finished %s" % (TLSCommModule.CNT, stream_id))
                
                self._set_server_finished_message_authenticated(sender_id, stream_id, received_hash, uuuid)
                                
                # send change cipher spec message
                yield self.sim_env.process(self.change_spec.send_cipher_spec(sender_id, stream_id))
                
                # send finished message
                yield self.sim_env.process(self._send_server_finished(sender_id, stream_id))
                
                
                
        # client finished
        if self._record.mode[sender_id][stream_id] == TLSConnectionEnd.CLIENT:  
                
            # logging
            uuuid, received_hash = self._set_client_finished_message_state(sender_id, stream_id, message), message
            
            # create comparables
            verification_hash, hashed = self._client_finished_verification_data(sender_id, stream_id)  
            
            # hash time
            time_hash, hashed_size = self._client_finish_hash_time()   
            yield self.sim_env.timeout(time_hash)
            
            # prf time
            yield self.sim_env.timeout(self._client_finished_prf_time(sender_id, hashed, hashed_size, stream_id, uuuid, verification_hash))

            print("Stream %s FINISHED" % stream_id)

            # compare
            if received_hash == verification_hash: self._set_client_finished_message_authenticated(sender_id, stream_id, received_hash, uuuid)                
            else: logging.warn("SEND AN ALERT!")     
            
            
            
        # delete done streams
        self.pre_master_secret[sender_id].pop(stream_id, None)     
    
        
        
#         ObjectMap().remove_unreferenced()
    
    def _handle_server_certificate(self, sender_id, message):
        ''' this method handles the server certificate message by simply
            caching it
        
            Input:  sender_id        string        id of the ECU that sent the message
                    message          object        server certificate message that needs to be processed
            Output: -             
        '''
        
        # set state
        stream_id = message[3][-1]      
#         print("%s Handle server certificate" % stream_id)  
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.SERVER_CERTIFICATE_RECEIVED)
        
        # monitor
        monitor_tag = MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE
        message_id = can_registration.CAN_TLS_SERVER_CERTIFICATE
        uid = uuid.uuid4().hex
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, self.sim_env.now, sender_id, message_id, message, 0, stream_id, uid))
        
        # dummy
        if False: yield self.sim_env.timeout(0)
    
       
    def _handle_server_hello(self, sender_id, message):
        ''' this method handles the server hello message by simply
            caching it
        
            Input:  sender_id        string        id of the ECU that sent the message
                    message          object        server hello message that needs to be processed
            Output: -             
        '''
        
        # set state
        stream_id = message[3][-1]        
#         print("%s Handle server hello" % stream_id)
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.SERVER_HELLO_RECEIVED)

        # monitor
        monitor_tag = MonitorTags.CP_RECEIVE_SERVER_HELLO
        message_id = can_registration.CAN_TLS_SERVER_HELLO
        uid = uuid.uuid4().hex
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, self.sim_env.now, sender_id, message_id, message, 0, stream_id, uid))
                            
        
        # dummy
        if False:  yield self.sim_env.timeout(0)
    
    
    def _handle_server_hello_done(self, sender_id, message):
        ''' this method handles the received server_hello done message. It validates the 
            certificate it received. Then it sends a certificate if requested and further 
            messages including the client key exchange, certificate verify, change cipher spec
            and the client finished message
            
            Input:  sender_id    string        id of the server with which this ecu is communicating via this stream
                    message      list          server hello done message that was received
            Output: -
                    
        '''
        # set state, save msg
        stream_id, u_id = self._set_server_hello_done_state(sender_id, message)
#         print("%s Handle server hello done" % stream_id)

        # validate certificate process
        cert = TLSCommModule.CERT_REUSE["Demo_Certificate"]
        lst_root_certs = TLSCommModule.CERT_LIST_REUSE["Demo_Certificate"].get()
        
        # validate Certificate process
        valid_cert = certificate_trustworthy(cert, lst_root_certs, self.sim_env.now)  # @UnusedVariable      
    
        # validate certificate time
        yield self.sim_env.timeout(self._validate_server_certificate_time(sender_id, message, stream_id, u_id))

        # Checks all serverhello parameters if they are ok
        server_params_ok = True  # TODo: Implement possibly      #@UnusedVariable                    
        
        # send certifiacte if requested
        yield self.sim_env.process(self._send_client_certificate(sender_id, stream_id))
        
        # send the client key exchange message
        yield self.sim_env.process(self._send_client_keyexchange(sender_id, stream_id))
        
        # send Certificate Verify
        yield self.sim_env.process(self._send_certificate_verify(sender_id, stream_id))
        
        # send change cipher spec order
        yield self.sim_env.process(self.change_spec.send_cipher_spec(sender_id, stream_id))
        
        # send finished message
        yield self.sim_env.process(self._send_client_finished(sender_id, stream_id))
    
       
    def _handle_server_key_exchange(self, sender_id, message):
        ''' receives the server key exchange message and hashes it
            
            Input:  sender_id    string    id of sender of the message
                    message      list      message that was received from the server         
            Output: -  
        '''
        # information
        stream_id = message[3][-1]
#         print("%s Handle server key exchange" % stream_id)
                
        # set state
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.SERVER_KEYEXCHANGE_RECEIVED)
        
        # dummy
        if False: yield self.sim_env.timeout(0)    
        
      
    def _hash_time_client_finished(self, sender_id, hashed, stream_id, uuuid):
        ''' time to hash the client finished message and the size of the 
            hashed message
        
            Input:  sender_id        string         id of the communication partner who will receive the server 
                                                    finished message
                    hashed           list           message to be hashed using the prf
                    stream_id        integer        id of the current communication stream
                    uuuid            hex            unique id corresponding to this message
            Output: hashed_size      float          size of the message after being hashed
                    hash_time        float          time to hash the message 
        '''
        # settings
        size = self._record.TLSH_CLIENT_SEND_FINISHED_CONTENT_SIZE
        algorithm = self._record.TLSH_FINISH_MESSAGE_HASH_ALGORITHM
        
        # hash size
        hashed_size = G().call_or_const(self._record.TLSH_CLIENT_SEND_FINISHED_HASH_SIZE, size, algorithm, None, 'HASH')
        
        # hash time
        hash_time = time.call(self._record.TLSH_CLIENT_SEND_FINISHED_HASH_TIME, size, algorithm) * self._jitter
        
        # monitor
        monitor_tag = MonitorTags.CP_HASHED_CLIENT_FINISHED
        now = self.sim_env.now + hash_time
        message_id = can_registration.CAN_TLS_FINISHED
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, hashed, hashed_size, stream_id, uuuid))
        
        # results
        return hashed_size, hash_time
    
    
    def _hash_time_server_finished(self, sender_id, hashed, stream_id, uuuid):
        ''' calculates the time needed to hash the server finished message. ABove
            that it returns the size of the resulting hash
            
            Input:  sender_id        string         id of the communication partner who will receive the server 
                                                    finished message
                    hashed           list           message to be hashed using the prf
                    stream_id        integer        id of the current communication stream
                    uuuid            hex            unique id corresponding to this message
            Output: hashed_size      float          size of the message after being hashed
                    hash_time        float          time to hash the message 
        '''
        # information
        content_size = self._record.TLSH_SERVER_SEND_FINISHED_CONTENT_SIZE
        algorithm = self._record.TLSH_FINISH_MESSAGE_HASH_ALGORITHM
        
        # size
        hashed_size = G().call_or_const(self._record.TLSH_SERVER_SEND_FINISHED_HASH_SIZE, content_size, algorithm, None, 'HASH')
        
        # time
        hash_time = time.call(self._record.TLSH_SERVER_SEND_FINISHED_HASH_TIME, content_size, algorithm) 
        hash_time *= self._jitter
        
        # monitor
        monitor_tag = MonitorTags.CP_HASHED_SERVER_FINISHED
        now = self.sim_env.now + hash_time
        message_id = can_registration.CAN_TLS_FINISHED
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, hashed, hashed_size, stream_id, uuuid))
        
        # result
        return hashed_size, hash_time
    
    
    def _log_sent_client_hello(self, receiver_id, clear_message, message_size, stream_id, uid):
        ''' this method logs the end of the client hello sending process
            
            Input:  receiver_id        string     id of the receiver
                    clear_message      list       client hello message
                    message_size       float      size of client hello message
                    stream_id          integer    id of the stream that is to be initialized
                    uid                hex        unique id corresponding to this message
            Output: -
        '''
        monitor_tag = MonitorTags.CP_SEND_CLIENT_HELLO
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CLIENT_HELLO
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, receiver_id, message_id, clear_message, message_size, stream_id, uid)) 
    
    
    def _prf_from_cipher_suite(self, cipher_suite):
        ''' 
            returns the prf depending on the selected cipher suite
            
            Input:    cipher_suite    TLSCipherSuite        cipher suite that was negotiated during handshake
            Output:   prf             function              pseudo random function  conforming with the cipher suite
        
            TODO: Implement depending on the suite
        '''
        prf = None        
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            prf = self._dummy_prf
        elif cipher_suite == TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
            prf = self._dummy_prf
        elif cipher_suite == TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
            prf = self._dummy_prf
        elif cipher_suite == TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
            prf = self._dummy_prf
        elif cipher_suite == TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
            prf = self._dummy_prf
        elif cipher_suite == TLSCipherSuite.TLS_RSA_WITH_NULL_MD5:
            prf = self._dummy_prf
        elif cipher_suite == TLSCipherSuite.TLS_RSA_WITH_NULL_SHA:
            prf = self._dummy_prf
        elif cipher_suite == TLSCipherSuite.TLS_RSA_WITH_NULL_SHA256:
            prf = self._dummy_prf
        elif cipher_suite == TLSCipherSuite.TLS_RSA_WITH_RC4_128_MD5:
            prf = self._dummy_prf
        elif cipher_suite == TLSCipherSuite.TLS_RSA_WITH_RC4_128_SHA:
            prf = self._dummy_prf        
        return prf
    
    
    def _public_key_from_server_message(self, server_id, stream_id):
        ''' returns the public key in the certificate of the cached
            server cerificate message
            
            Input:  server_id        string            id of the target server
                    stream_id        integer           corresponding stream id to this communication
            Output: public_key       AsymmetricKey     public key of the server certificate            
        '''

        # server certificate
        server_certificate = TLSCommModule.CERT_REUSE["Demo_Certificate"]
        
        # key
        public_key = server_certificate.pub_key_user
    
        return public_key
    
    
    def _send_alert_no_cipher_suite(self):
        ''' not implemented '''
        return
    
    
    def _send_certificate_request(self, client_id, stream_id):
        ''' sends the certificate request message to the client with id 
            client_id
            
            Input:  client_id        string        id of the target client
                    stream_id        integer       corresponding stream id to this communication
            Output: -
        '''
        
        # set state
        G().add_to_three_dict(self._record.state, client_id, stream_id, TLSState.CLIENT_CERTIFICATE_REQUEST_SENT)
        
        # generate message
        certificate_type, sign_hash_algorithms, accepted_cas_list = self._generate_message_components_cert_request()
                
        # Create message
        clear_message = [certificate_type, sign_hash_algorithms, accepted_cas_list, stream_id]        
        message_size = G().call_or_const(self._record.TLSH_CERT_REQUEST_SEND_SIZE)
        message = SegData(clear_message, message_size)
        
        # send message
        now = self.sim_env.now        
        uid = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_SEND_CERTIFICATE_REQUEST
        message_id = can_registration.CAN_TLS_CERTIFICATE_REQUEST        
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, client_id, message_id, message, message_size, stream_id, uid))
                
        # send message
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_CERTIFICATE_REQUEST, message, TLSContentType.HANDSHAKE, client_id, stream_id))
    
    
    def _send_certificate_verify(self, server_id, stream_id):
        ''' sends the certificate verify message to the server with id 
            server_id
            
            Input:  server_id        string        id of the target server
                    stream_id        integer       corresponding stream id to this communication
            Output: -
        '''
        
        # set state, save msg
        G().add_to_three_dict(self._record.state, server_id, stream_id, TLSState.CERTIFICATE_VERIFY_SENT)       
        uuu_id = uuid.uuid4().hex
        
        # create message
        clear_message, public_key = self._generate_certificate_verify_clear(server_id, stream_id, uuu_id)
                
        # encrypt with certificate key
        encrypted_msg = encryption_tools.asy_encrypt(clear_message, public_key)        
        
        # Time to encrypt
        cipher_size, encryption_time = self._certificate_verify_encryption_time_size()        
        yield self.sim_env.timeout(encryption_time)

        # prepare and send
        message = self._sendable_certificate_verify(cipher_size, encrypted_msg, stream_id, server_id, clear_message, uuu_id)
        
        # send message
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_CERTIFICATE_VERIFY, message, TLSContentType.HANDSHAKE, server_id, stream_id))
    
          
    def _send_client_certificate(self, server_id, stream_id):
        ''' sends the client certificate message to the server with 
            server_id while establishment of the stream with id 
            stream_id
            
            Input:  server_id        string        id of the target server
                    stream_id        integer       corresponding stream id to this communication
            Output: -
            
        '''
        # set state
        G().add_to_three_dict(self._record.state, server_id, stream_id, TLSState.CLIENT_CERTIFICATE_SENT)

        # generate a certificate with negotiated cipher suite algorithms
        ca_length = 1
        suite = TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
        certificate, root_certificate_list, priv_key = self._certificate_from_cipher_suite(suite, ca_length)  # @UnusedVariable
          
        # sendable message
        message, clear_message = self._sendable_client_certificate(certificate, root_certificate_list, stream_id, server_id)


        # send message        
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_CERTIFICATE, message, TLSContentType.HANDSHAKE, server_id, stream_id))
    
    
    def _send_client_finished(self, sender_id, stream_id):
        ''' this method sends the client finished message using the
            transport layer.
            
            Input:   sender_id      string         id of the communication partner who will receive the server 
                                                   finished message
                    stream_id       integer        id of the current communication stream
            Output: -        
        '''
        # current settings
        mac_algorithm = self._record._w_pending_sec_params[sender_id][stream_id].mac_algorithm
        prf_algorithm = self._record.TLSH_CLIENT_SEND_FINISHED_PRF_ALG
        master_secret = self._record._w_pending_sec_params[sender_id][stream_id].master_secret
        
        # set state
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.FINISHED_SENT)

        # get cached messages
        clear_message, prf, uuuid = self._create_client_finished_clear_message(sender_id, stream_id)
        hashed = [str(clear_message), mac_algorithm]  # hashed message dummy        
        verification_data = prf(master_secret, "client finished", str(hashed))
        
        # hash time
        hashed_size, time_hash = self._hash_time_client_finished(sender_id, hashed, stream_id, uuuid)             
        yield self.sim_env.timeout(time_hash)
        
        # prf time
        input_size = len(master_secret) + len("client finished") + hashed_size
        prf_time = time.call(self._record.TLSH_PRF_WORKING_TIME, input_size, prf_algorithm)
        yield self.sim_env.timeout(prf_time)

        # sendable
        message = self._sendable_client_finished_message(verification_data, stream_id, sender_id, uuuid)
        
        # send
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_FINISHED, message, TLSContentType.HANDSHAKE, sender_id, stream_id))
    
    
    def _send_client_keyexchange(self, server_id, stream_id):
        ''' this method sends the client keyexchange message to the server with id
            server_id on the session with stream id stream_id
            
            Input:  server_id        string        id of the target server
                    stream_id        integer       corresponding stream id to this communication
            Output: -
        '''
        
        # set state
        G().add_to_three_dict(self._record.state, server_id, stream_id, TLSState.CLIENT_KEYEXCHANGE_SENT)
                
        # create premaster secret (48 Byte)
        pre_master_secret, uuu_id = self._client_generate_premaster_secret(server_id, stream_id)
                
        # encrypt (public key of servers certificate)
        public_key = self._public_key_from_server_message(server_id, stream_id)
        encrypted_msg = encryption_tools.asy_encrypt(pre_master_secret, public_key)

        # encryption time
        encryption_time, cipher_size = self._client_key_exchange_encryption_time(server_id, stream_id, pre_master_secret, uuu_id)
        yield self.sim_env.timeout(encryption_time)
        
        # set pending configurations
        yield self.sim_env.process(self._client_key_exchange_set_pending_configuration(server_id, stream_id, pre_master_secret, uuu_id))
                                                
        # prepare message
        message_size = cipher_size
        message = SegData([encrypted_msg, stream_id], message_size) 
        
        # send message       
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE, message, TLSContentType.HANDSHAKE, server_id, stream_id))
    
         
    def _send_server_certificate(self, client_id, stream_id):
        ''' this method sends the server certificate message to the client with
            client_id via the stream with stream_id
        
            Input:  client_id        string        id of the target client
                    stream_id        integer       id of the current session
            Output: - 
        '''
        # information
        ca_length = 1
        cipher_suite = self._record.negotiated_cipher_suite[client_id][stream_id]       
        
        # set state
        G().add_to_three_dict(self._record.state, client_id, stream_id, TLSState.SERVER_CERTIFICATE_SENT)
        
        # server certificate (with negotiated cipher suite algorithms)        
        server_certificate, server_root_certificates, private_key = self._certificate_from_cipher_suite(cipher_suite, ca_length)
                
        # client certificate
        certificate = server_certificate
        root_certificate_list = server_root_certificates
        
        # cache
        G().add_to_three_dict(self._record.server_cert_priv_keys, client_id, stream_id, private_key)
        
        # prepare message
        message = self._sendable_server_certificate(certificate, root_certificate_list, stream_id, client_id)
        
        # send message        
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_SERVER_CERTIFICATE, message, TLSContentType.HANDSHAKE, client_id, stream_id))  
    
    
    def _send_server_finished(self, sender_id, stream_id):
        ''' this method sends the server finished message using the
            transport layer.
            
            Input:   sender_id      string         id of the communication partner who will receive the server 
                                                   finished message
                    stream_id       integer        id of the current communication stream
            Output: -        
        '''
        
        # current parameters
        mac_algorithm = self._record._w_current_sec_params[sender_id][stream_id].mac_algorithm
        master_secret = self._record._w_current_sec_params[sender_id][stream_id].master_secret
        
        # set state
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.FINISHED_SENT)
        
        # create cached messages
        clear_message, prf, uuuid = self._create_server_finished_clear_message(sender_id, stream_id)
        hashed = [str(clear_message), mac_algorithm]  # hashed message dummy        
        verification_data = prf(master_secret, "client finished", str(hashed))

        # hash time
        hashed_size, hash_time = self._hash_time_server_finished(sender_id, hashed, stream_id, uuuid)        
        yield self.sim_env.timeout(hash_time)

        # PRF time
        input_size = len(master_secret) + len("client finished") + hashed_size
        prf_time = time.call(self._record.TLSH_PRF_WORKING_TIME, input_size, self._record.TLSH_SERVER_SEND_FINISHED_PRF_ALG)
        yield self.sim_env.timeout(prf_time)
        
        # message to send
        message = self._sendable_server_finished_message(verification_data, stream_id, sender_id, uuuid)
        
        # send message
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_FINISHED, message, TLSContentType.HANDSHAKE, sender_id, stream_id))
    
    
    def _send_server_hello(self, client_hello, client_id, stream_id):
        ''' sends the server hello message to the target client with id client_id
            during the session handshake with id stream_id
        
            Input:  client_hello     list          client hello message
                    client_id        string        id of the client
                    stream_id        integer       id of the session coresponding to this handshake
            Output: - 
        '''
        
        # set states
        G().add_to_three_dict(self._record.state, client_id, stream_id, TLSState.SERVER_HELLO_SENT)

        # determine message content
        protocol_ver = self._record.TLSRL_PROTOCOL_VERSION
        
        if "SERVER_HELLO" in TLSCommModule.RANDOM_BYTES.keys():
            random_bytes = TLSCommModule.RANDOM_BYTES["SERVER_HELLO"]
        else:
            random_bytes = os.urandom(28)
            TLSCommModule.RANDOM_BYTES["SERVER_HELLO"] = random_bytes  
            
        
        session_id = uuid.uuid4().hex
        cipher_suite = client_hello[3][4].get()[0]  # select first ciphersuite
        compression_method = client_hello[3][5]
        
        # create message
        clear_message = [protocol_ver, random_bytes, session_id, cipher_suite, compression_method, stream_id]
        message_size = G().call_or_const(self._record.TLSH_SERVER_HELLO_SEND_SIZE)
        message = SegData(clear_message, message_size)
        
        # add selected cipher suite to cache
        self._cache_server_hello(client_id, stream_id, clear_message, message_size, cipher_suite, compression_method)
        
        # send message                
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_SERVER_HELLO, message, TLSContentType.HANDSHAKE, client_id, stream_id))  
    
    
    def _send_server_hello_done(self, client_id, stream_id):
        ''' sends the server hello done message to the target client with id client_id
            during the session handshake with id stream_id
        
            Input:  client_id        string        id of the client
                    stream_id        integer       id of the session coresponding to this handshake
            Output: - 
        '''
        # set state
        G().add_to_three_dict(self._record.state, client_id, stream_id, TLSState.SERVER_HELLO_DONE_SENT)
 
        # create message
        clear_message = [stream_id]
        message_size = G().call_or_const(self._record.TLSH_SERVER_HELLO_DONE_SEND_SIZE)
        message = SegData(clear_message, message_size)
        
        # monitor
        monitor_tag = MonitorTags.CP_SEND_SERVER_HELLO_DONE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, self.sim_env.now, client_id, can_registration.CAN_TLS_SERVER_HELLO_DONE, clear_message, message_size, stream_id, uuid.uuid4().hex))
        
        
        # send message
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_SERVER_HELLO_DONE, message, TLSContentType.HANDSHAKE, client_id, stream_id))
    
    
    def _send_server_key_exchange(self, client_id, stream_id):
        ''' this method is only sent for DHE_DSS, DHE_RSA, DH_anon. It sends
            the server key exchange message if defined
            
            Input:  client_id        string        id of the client
                    stream_id        integer       id of the session coresponding to this handshake
            Output: -
        '''
        
        # initialize
        G().add_to_three_dict(self._record.state, client_id, stream_id, TLSState.SERVER_KEYEXCHANGE_SENT)
        dh_p, dh_g, dh_Ys, key_exch_alg, server_dh_params = 0, 0, 0, KeyexchangeAlgorithm.RSA, []
        
        # sent if certain algorithms
        if (key_exch_alg not in [KeyexchangeAlgorithm.DH_ANON, KeyexchangeAlgorithm.DHE_RSA, KeyexchangeAlgorithm.DHE_DSS]): return 
        
        # for RSA the following holds
        if key_exch_alg in [KeyexchangeAlgorithm.RSA, KeyexchangeAlgorithm.DH_RSA, KeyexchangeAlgorithm.DH_DSS]:
            msg_clear = [key_exch_alg, server_dh_params, stream_id]
            message_size = 25        
        elif key_exch_alg == KeyexchangeAlgorithm.DH_ANON:
            logging.error("Not implemented DH ANON")            
        elif key_exch_alg == KeyexchangeAlgorithm.DHE_DSS:
            logging.error("Not implemented DHE DSS")
        elif key_exch_alg == KeyexchangeAlgorithm.DHE_RSA:
            server_dh_params = [dh_p, dh_g, dh_Ys]
            client_random = 123  # 32 bytes
            server_random = 213  # 32 bytes
            msg_clear = [client_random, server_random, server_dh_params, stream_id]
            message_size = 72
                
        # monitor
        G().mon(self.monitor_lst, MonitorInput([], MonitorTags.CP_SEND_SERVER_KEYEXCHANGE, self._ecu_id, self.sim_env.now, client_id, \
                                               can_registration.CAN_TLS_SERVER_KEY_EXCHANGE, msg_clear, 0, stream_id, uuid.uuid4().hex))
                
        # send message
        message = SegData(msg_clear, message_size)
        yield self.sim_env.process(self._record.send(self.ecu_id, can_registration.CAN_TLS_SERVER_KEY_EXCHANGE, message, \
                                                     TLSContentType.HANDSHAKE, client_id, stream_id))   
    
    
    def _sendable_certificate_verify(self, cipher_size, encrypted_msg, stream_id, server_id, clear_message, uuu_id):
        ''' cretes the sendable version of the certificate verify message
            
            Input:  cipher_size       float                  size of the message after encryption
                    encrypted_msg     EncryptedMessage       message that will be sent 
                    stream_id         integer                stream_id corresponding to this session
                    server_id         string                 id of server communicating with this ecu
                    clear_message     list                   message to be sent before encryption 
                    uuu_id            hex                    unique id of this message
            Output: message           SegData                sendable version of the certificate verify message
        
        '''
        
        # message
        message_size = cipher_size
        message = SegData([encrypted_msg, stream_id], message_size) 
                
        # monitor
        monitor_tag = MonitorTags.CP_ENCRYPTED_CERTIFICATE_VERIFY
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CLIENT_KEY_EXCHANGE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, server_id, message_id, encrypted_msg, message_size, stream_id, uuu_id))
        
        # result
        return message
    
            
    def _sendable_client_certificate(self, certificate, root_certificate_list, stream_id, server_id):
        ''' this method returns the sendable version of the 
            client certificate together with its  message content
            unwrapped
            
            Input:  certificate                ECUCertificate    certificate of the client ECU
                    root_certificate_list      list              list of root certificates to verify this certificate
                    stream_id                  integer           corresponding stream id to this communication
                    server_id                  string            id of the target server
            Output: message                    SegData           messsage wrapped to be sendable 
                    clear_message              list              message before wrapping
        '''
        
        # content
        clear_message = [certificate, root_certificate_list, stream_id]
        message_size = self._record.TLSH_CERT_SEND_SIZE + (len(root_certificate_list.get()) - 1) * self._record.TLSH_CERT_SEND_SIZE
        
        # message
        message = SegData(clear_message, message_size)     
        
        # monitor
        monitor_tag = MonitorTags.CP_SEND_CLIENT_CERTIFICATE
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CERTIFICATE
        uid = uuid.uuid4().hex
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, server_id, message_id, clear_message, message_size, stream_id, uid))
              
        return message, clear_message
    
      
    def _sendable_client_finished_message(self, verification_data, stream_id, sender_id, uuuid):
        ''' this message generates the sendable client finished message 
            as it is put on the transport layer
        
            Input:  verification_data    string     byte string containing the hashed data used to verify this message
                    sender_id        string         id of the communication partner who will receive the server 
                                                    finished message
                    stream_id        integer        id of the current communication stream
                    uuuid            hex            unique id corresponding to this message
            Output: message          SegData        sendable client finished message        
        '''
        
        # message size
        message_size = len(verification_data)
        
        # message
        message = SegData([verification_data, stream_id], message_size)
        
        # monitor
        monitor_tag = MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, \
                                               message_id, verification_data, message_size, stream_id, uuuid))
        
        # result
        return message
    
      
    def _sendable_server_certificate(self, certificate, root_certificate_list, stream_id, client_id):
        ''' returns the sendable version of the server certificate message to the target client 
            with id client_id over the stream with id stream_id
            
            Input:  certificate              ECUCertificate    client certificate
                    root_certificate_list    list              list of root certificates for the client certificate
                    stream_id                integer           id of the current session
                    client_id                string            id of the target client 
        '''
        
        # clear message
        clear_message = [certificate, root_certificate_list, stream_id]
        
        # size
        message_size = self._record.TLSH_CERT_SEND_SIZE + (len(root_certificate_list.get()) - 1) * self._record.TLSH_CERT_SEND_SIZE
        
        # message
        message = SegData(clear_message, message_size)        
         
        # monitor
        now = self.sim_env.now
        uid = uuid.uuid4().hex
        message_id = can_registration.CAN_TLS_SERVER_CERTIFICATE
        monitor_tag = MonitorTags.CP_SEND_SERVER_CERTIFICATE        
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, client_id, message_id, clear_message, message_size, stream_id, uid))
       
        # result
        return message
    
    
    def _sendable_server_finished_message(self, verification_data, stream_id, sender_id, uuuid):
        ''' this message generates the sendable server finished message 
            as it is put on the transport layer
        
            Input:  verification_data    string     byte string containing the hashed data used to verify this message
                    sender_id        string         id of the communication partner who will receive the server 
                                                    finished message
                    stream_id        integer        id of the current communication stream
                    uuuid            hex            unique id corresponding to this message
            Output: message          SegData        sendable server finished message        
        '''

        # message size
        message_size = len(verification_data)
        
        # message
        message = SegData([verification_data, stream_id], message_size)
                
        # monitor
        monitor_tag = MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, \
                                               message_id, verification_data, message_size, stream_id, uuuid))
        
        # return result
        return message
        
    
    def _server_finish_hash_time(self):
        ''' this method calculates the hashing time needed to 
            hash the cached messages when the finished message 
            was received at server side
            
            Input:     -
            Output:    hashing_time    float    time to hash the cached messages
                       hashed_size     float    size of the hashed message            
        '''
        # information
        content_size = self._record.TLSH_SERVER_REC_FINISHED_CONTENT_SIZE
        algorithm = self._record.TLSH_FINISH_MESSAGE_HASH_ALGORITHM    
        
        # size
        hashed_size = G().call_or_const(self._record.TLSH_SERVER_REC_FINISHED_HASH_SIZE, content_size, algorithm, None, 'HASH')        
        
        # time
        hashing_time = time.call(self._record.TLSH_SERVER_REC_FINISHED_HASH_TIME, content_size, algorithm) * self._jitter
    
        return hashing_time, hashed_size
    
    
    def _server_finished_prf_time(self, sender_id, hashed, hashed_size, stream_id, uuuid, verification_hash):
        ''' this method calculates the time it takes to run the prf method
            that generates the comparison hash in the server finished message
            
            Input:  sender_id                string         id of the ECU that sent the message
                    hashed                   list           list of the clear verification message and the algorithm
                    hashed_size              float          size of the hashed message        
                    stream_id                integer        if of the stream corresponding to this finished message
                    uuuid                    hex            unique id corresponding to this message
                    verification_hash        bytes          byte string that is used to verify the received messages
            Output: prf_time                 float          time to generate the hash from the PRF  
        '''
        # monitor
        monitor_tag = MonitorTags.CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, hashed, hashed_size, stream_id, uuuid))
        
        # information
        master_secret = self._record._r_current_sec_params[sender_id][stream_id].master_secret
        
        # input size
        input_size = len(master_secret) + len("client finished") + hashed_size
        
        # prf time
        prf_time = time.call(self._record.TLSH_PRF_WORKING_TIME, input_size, self._record.TLSH_SERVER_REC_FINISHED_PRF_ALG)

        # monitor
        monitor_tag = MonitorTags.CP_CLIENT_FINISHED_GENERATED_HASH_PRF
        now = self.sim_env.now + prf_time
        message_id = can_registration.CAN_TLS_FINISHED
        size = len(verification_hash)
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, verification_hash, size, stream_id, uuuid))
    
        # result
        return prf_time
    
    
    def _server_finished_verification_data(self, sender_id, stream_id):
        ''' this method generates the hash that is used for verification after
            the server received its finished message. This verification hash 
            is built from all messages that were sent and received during the
            stream with this id and the sender with this id.
            
            Input:  sender_id            string         id of the ECU that sent the message
                    stream_id            integer        if of the stream corresponding to this finished message
            Output: verification_hash    bytes          byte string that is used to verify the received messages
                    hashed               list           list of the clear verification message and the algorithm
        '''
        
        # determine PRF
        prf = self._prf_from_cipher_suite(self._record.negotiated_cipher_suite[sender_id][stream_id]) 
        
        # determine negotiated algorithm
        mac_algorithm = self._record._r_current_sec_params[sender_id][stream_id].mac_algorithm
        master_secret = self._record._r_current_sec_params[sender_id][stream_id].master_secret
        
        # gather cached messages
        msg_clear = [0]
        
        # hash
        hashed = [str(msg_clear), mac_algorithm]   
        verification_hash = prf(master_secret, "client finished", str(hashed))
        
        
        return verification_hash, hashed
    
    
    def _set_client_finished_message_authenticated(self, sender_id, stream_id, received_hash, uuuid):
        ''' once the client received the finished message and has
            successfully verified it the state of this ecu
            towards the sender ecu and its stream id is set
            to authenticated. After this message the sending of 
            the messages can begin
            
            Input:  sender_id        string         id of the ECU that sent the finished message
                    stream_id        integer        if of the stream corresponding to this finished message
                    received_hash    bytes          byte string that was received in the finished message  
                    uuuid            hex            unique id corresponding to this message
            Output: -
        '''     
        # set state
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.AUTHENTICATED)
        
        # monitor
        monitor_tag = MonitorTags.CP_SERVER_AUTHENTICATED
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        size = len(received_hash)
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, received_hash, size, stream_id, uuuid))
        
        # log
        log_str = "\n-------------------------------------------------------------------------------------------------"
        log_str += "\n Client %s was authenticated for this session at Server %s- Stream: %s" % (self.ecu_id, sender_id, stream_id)
        log_str += "\n-------------------------------------------------------------------------------------------------\n"        
#         logging.info(log_str)
    
        # message authenticated
        TLSCommModule.KX_ACTUAL_NUMBER[stream_id] += 1
        if TLSCommModule.KX_ACTUAL_NUMBER[stream_id] == TLSCommModule.KX_EXPECTED_NUMBER[stream_id]:
            try:
                TLSCommModule.KX_SETUP_NOTIFY_STORES[stream_id].put(True)
                del TLSCommModule.KX_ACTUAL_NUMBER[stream_id]
                del TLSCommModule.KX_EXPECTED_NUMBER[stream_id]
            except:pass
    
    def _set_client_finished_message_state(self, sender_id, stream_id, message):
        ''' once the client received the finished message the corresponding 
            state and mode have to be set. This is done here.
            
            Input:  sender_id        string         id of the ECU that sent the finished message
                    stream_id        integer        if of the stream corresponding to this finished message
                    message          list           clear finished message
            Output: uuuid            hex            unique id corresponding to this message
        '''
        
        # monitor
        monitor_tag = MonitorTags.CP_RECEIVE_SERVER_FINISHED
        uuuid = uuid.uuid4().hex
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, message, len(message), stream_id, uuuid))
        
        
        return uuuid
        
    
    def _set_record_layer_spec_certificate_verify(self, sender_id, stream_id, master_secret, server_random, client_random, uuuid):
        ''' after the parameters were negotiated successfully the negotiated parameters are set to the pending write/read state.
            Once the ChangeCipherSpec Message is received this cipher parameters will be used for decryption and encryption of 
            messages on the record layer
            
            Input:  sender_id        string     id of the ECU sending the certificate verify message
                    stream_id        integer    stream id corresponding to this message
                    master_secret    string     master secret generated from negotiated  
                    server_random    string     random string of server    
                    client_random    string     random string of client
                    uuuid            hex        unique id corresponding to this message
            Output: -
        
        '''
        # parameters
        cipher_suite = self._record.negotiated_cipher_suite[sender_id][stream_id]
        compress_method = self._record.negotiated_compression_method[sender_id][stream_id]
        mode = TLSConnectionEnd.CLIENT
        
        # monitor 
        monitor_tag = MonitorTags.CP_GENERATED_MASTER_SECRET_CERT_VERIFY
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_CERTIFICATE_VERIFY
        size = len(master_secret)
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, master_secret, size, stream_id, uuuid))
        
        # add pending read state
        G().add_to_three_dict(self._record._r_pending_sec_params, sender_id, stream_id, TLSSecurityParameter())
        self._record._r_pending_sec_params[sender_id][stream_id].from_cipher_suite(mode, cipher_suite, compress_method, master_secret, \
                                                                                   server_random, client_random, self._dummy_prf)
        
        # add pending write state
        G().add_to_three_dict(self._record._w_pending_sec_params, sender_id, stream_id, TLSSecurityParameter())
        self._record._w_pending_sec_params[sender_id][stream_id].from_cipher_suite(mode, cipher_suite, compress_method, master_secret, \
                                                                                   server_random, client_random, self._dummy_prf)   
        
        # generate keys at record layer
        if self._record._w_current_sec_params[sender_id][stream_id].master_secret == None:
            pending_w = self._record._w_pending_sec_params[sender_id][stream_id]
            pending_r = self._record._r_pending_sec_params[sender_id][stream_id]
            self._record.set_keys_from_sec_par(pending_w, pending_r, sender_id, stream_id)
    
    
    def _set_server_finished_message_authenticated(self, sender_id, stream_id, received_hash, uuuid):
        ''' once the server received the finished message and has
            successfully verified it the state of this ecu
            towards the sender ecu and its stream id is set
            to authenticated
            
            Input:  sender_id        string         id of the ECU that sent the finished message
                    stream_id        integer        if of the stream corresponding to this finished message
                    received_hash    bytes          byte string that was received in the finished message  
                    uuuid            hex            unique id corresponding to this message
            Output: -
        '''
        # set state
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.AUTHENTICATED)
        
        # monitor
        monitor_tag = MonitorTags.CP_CLIENT_AUTHENTICATED
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        size = len(received_hash)
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, \
                                               message_id, received_hash, size, stream_id, uuuid))
        
        # log
        log_str = "\n-------------------------------------------------------------------------------------------------"
        log_str += "\n Server %s granted authentication to Client %s - Stream: %s" % (self.ecu_id, sender_id, stream_id)
        log_str += "\n-------------------------------------------------------------------------------------------------\n"        
#         logging.info(log_str)
        
    
    def _set_server_finished_message_state(self, sender_id, stream_id, message):
        ''' once the server received the finished message the corresponding 
            state and mode have to be set. This is done here.
            
            Input:  sender_id        string         id of the ECU that sent the finished message
                    stream_id        integer        if of the stream corresponding to this finished message
                    message          list           clear finished message
            Output: uuuid            hex            unique id corresponding to this message
        '''
        
        # monitor
        uuuid = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_RECEIVE_CLIENT_FINISHED
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_FINISHED
        size = len(message)
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, message, size, stream_id, uuuid))
        
        return uuuid
     
    
    def _set_server_hello_done_state(self, sender_id, message):
        ''' this method sets the ECU state after the server hello done message was 
            received. Moreover it saves the cipher suite and the compression method that
            was negotiated with the partner. Additionaly it monitors this event and returns the 
            stream id of the message.
            
            Input:  sender_id    string        id of the server with which this ecu is communicating via this stream
                    message      list          server hello done message that was received
            Output: stream_id    integer       id of the stream 
                    u_id         hex           unique identifier corresponding to the message 
        '''
        # extract stream id
        stream_id = message[3][-1]
        
        # set state
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.SERVER_HELLO_DONE_RECEIVED)
                
        # monitor
        u_id = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_RECEIVE_SERVER_HELLO_DONE
        now = self.sim_env.now
        message_id = can_registration.CAN_TLS_SERVER_HELLO_DONE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, message, 0, stream_id, u_id))
                
        # result
        return stream_id, u_id
        
    
    def _validate_server_certificate_time(self, sender_id, message, stream_id, u_id):
        ''' this method returns the time it takes to verify the server certificate that
            was received in the server_hello_done message
            
            Input:     sender_id           string       id of the server with which this ecu is communicating via this stream
                       message             list         server hello done message that was received
                       stream_id           integer      id of the current stream id 
                       u_id                hex          unique identifier for the send message
            Output:    validation_time     float        time to validate the server's certificate
        '''
        # information
        encryption_algorithm = self._record.TLSH_SERV_CERT_ENC_ALG
        encryption_key_length = self._record.TLSH_SERV_CERT_ENC_KEY_LEN
        encryption_algorithm_option = self._record.TLSH_SERV_CERT_ENC_ALG_OPTION
        hash_algorithm = self._record.TLSH_SERV_CERT_HASH_MECH
        ca_length = self._record.TLSH_SERV_CERT_CA_LEN
        
        # hashed size
        hash_size = EncryptionSize().output_size(self._record.TLSH_SERV_CERT_UNSIGNED_SIZE, hash_algorithm, None, 'HASH') 
        
        # signature size
        signed_size = G().call_or_const(self._record.TLSH_SERV_CERT_SIGNED_SIZE, hash_size, encryption_algorithm, encryption_key_length, 'SIGN')  # sign the hash
        
        # validation time
        validation_time = time.call(self._record.TLSH_SERV_HELLO_DONE_VERIFY_CERT_TIME, hash_algorithm, encryption_algorithm, encryption_key_length, \
                                    ca_length, self._record.TLSH_SERV_CERT_UNSIGNED_SIZE, signed_size, encryption_algorithm_option, self._record.TLSH_CERT_SEND_SIZE)
        
        # monitor
        monitor_tag = MonitorTags.CP_SERVER_HELLO_DONE_VALIDATED_CERT
        now = self.sim_env.now + validation_time
        message_id = can_registration.CAN_TLS_SERVER_HELLO_DONE
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, message, 0, stream_id, u_id))
        
        # return time
        return validation_time
                
class TLSAlert(object):
    '''
    sends the alert messages when needed
    '''
    
    def __init__(self, sim_env, tls_record, ecu_id, monitor_lst=[], jitter=1):
        ''' Constructor    
        
            Input:  sim_env         simpy.Environment        environment of this component
                    tls_record      TLSRecordLayer           record layer connected to this module
                    ecu_id          string                   id of the component holding this module
                    monitor_lst     RefList                  list used to update the monitor
                    jitter          float                    random value multiplied on each timeout
            Output: -
        '''
        self.sim_env = sim_env
        self.ecu_id = ecu_id
        self.monitor_lst = monitor_lst
        self._record = tls_record
        self._jitter = jitter
        
    def process(self, msg):
        ''' invoked when tls alert messages were sent'''
        pass
        
class TLSChangeCipherSpec(object):
    '''
    sends the change cipher spec protocol messages when needed
    '''
    def __init__(self, sim_env, tls_record, ecu_id, handshake, monitor_lst=[], jitter=1):
        ''' Constructor    
        
            Input:  sim_env         simpy.Environment        environment of this component
                    tls_record      TLSRecordLayer           record layer connected to this module
                    ecu_id          string                   id of the component holding this module
                    handshake       TLSHandshake             tls handshake class coresponding to this communication module
                    monitor_lst     RefList                  list used to update the monitor
                    jitter          float                    random value multiplied on each timeout
            Output: -
        '''
        # initialize
        self.sim_env = sim_env
        self.monitor_lst = monitor_lst
        self.ecu_id = ecu_id        
        self._handshake = handshake
        self._record = tls_record        
        self._jitter = jitter
    
    
    def process(self, sender_id, message_id, clear_message):
        ''' this method handles messages received by the communication module
            that use the handshake protocol
        
            Input:  sender_id        string     id of the sender that sent the message
                    message_id       integer    id of the received message
                    clear_message    SegData    clear message that was received from the record layer
            Output: -
        '''
        # stream id
        try: stream_id = clear_message[3][-1]
        except: return

        # Check state against incoming        
        if message_id == can_registration.CAN_TLS_CHANGE_CIPHER_SPEC:            
            if self._record.state[sender_id][stream_id] in [TLSState.CERTIFICATE_VERIFY_RECEIVED, TLSState.CLIENT_KEYEXCHANGE_RECEIVED, TLSState.FINISHED_SENT]: 
                yield self.sim_env.process(self._handle_change_cipher_spec(clear_message, sender_id))    

    
    def send_cipher_spec(self, receiver_id, stream_id):       
        ''' sends the cipher spec message to the receiver with id
            receiver_id over the session with id stream_id
            
            Input:  receiver_id    string     id of the ECU that will receive the cipher spec message
                    stream_id      integer    id of the session id for this communication
            Output: -            
        '''
        
        # allowed states
        allowed_states = [TLSState.CERTIFICATE_VERIFY_SENT, TLSState.FINISHED_RECEIVED, TLSState.AUTHENTICATED]
        if self._record.state[receiver_id][stream_id] in  allowed_states:
            
            # create message
            message = SegData([1, stream_id], 1)        
            
            # set state
            self._record.state[receiver_id][stream_id] = TLSState.CHANGE_CIPHER_SPEC_SENT
            
            # monitor
            self._monitor_send_cipher_spec(receiver_id, stream_id, message)
            
            # send message
            message_id = can_registration.CAN_TLS_CHANGE_CIPHER_SPEC
            content_type = TLSContentType.CHANGE_CIPHER_SPEC
            yield self.sim_env.process(self._record.send(self.ecu_id, message_id, message, content_type, receiver_id, stream_id))  
        
    
    def _handle_change_cipher_spec(self, clear_message, sender_id):
        ''' handles the change cipher spec message once received
            
            Input:  clear_message    list        change cipher spec message after decryption
                    sender_id        string      id of the ECU that send the change cipher spec message  
        '''
        # set state
        stream_id = clear_message[3][-1]
        G().add_to_three_dict(self._record.state, sender_id, stream_id, TLSState.CHANGE_CIPHER_SPEC_RECEIVED)
        
        # monitor
        self._monitor_handle_cipher_spec(sender_id, stream_id, clear_message)

        # push pending cipher suite 
        self._record.push_pending(sender_id, stream_id)
        
        # dummy
        if False: yield self.sim_env.timeout(0)

    
    def _monitor_handle_cipher_spec(self, sender_id, stream_id, clear_message):
        ''' monitors the handle change cipher spec 
            procedure
            
            Input:  sender_id          string     id of the ECU that sent the cipher spec message
                    stream_id          integer    id of the session id for this communication
                    clear_messag       list       change cipher spec message received
            Output: - 
        '''
        # monitor
        content = clear_message[3]
        uid = uuid.uuid4().hex
        monitor_tag = MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC
        message_id = can_registration.CAN_TLS_CHANGE_CIPHER_SPEC
        
        # monitor apply
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, self.sim_env.now, sender_id, message_id, content, 1, stream_id, uid))

    
    def _monitor_send_cipher_spec(self, receiver_id, stream_id, message):        
        ''' monitors the send cipher spec procedure 
            
            Input:  receiver_id    string     id of the ECU that will receive the cipher spec message
                    stream_id      integer    id of the session id for this communication
                    message        SegData    sendable change cipher spec message
            Output: - 
        '''
        # monitor
        monitor_tag = MonitorTags.CP_SEND_CIPHER_SPEC
        message_id = can_registration.CAN_TLS_CHANGE_CIPHER_SPEC
        content = message.get()
        uid = uuid.uuid4().hex
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, self.sim_env.now, receiver_id, message_id, content, 1, stream_id, uid))

class TLSApplicationTransmit(object):
    '''
    receives simple authenticated application messages
    '''    
    def __init__(self, sim_env, tls_record, ecu_id, monitor_lst=[], jitter=1):
        ''' Constructor    
        
            Input:  sim_env         simpy.Environment        environment of this component
                    tls_record      TLSRecordLayer           record layer connected to this module
                    ecu_id          string                   id of the component holding this module
                    handshake       TLSHandshake             tls handshake class coresponding to this communication module
                    monitor_lst     RefList                  list used to update the monitor
                    jitter          float                    random value multiplied on each timeout
            Output: -
        '''
        self.sim_env = sim_env
        self._record = tls_record
        self.ecu_id = ecu_id
        self.monitor_lst = monitor_lst
        self._jitter = jitter

    
    def process(self, sender_id, message_id, clear_message):
        ''' receives messages for the application and monitors 
            this event
            
            Input:  sender_id        string     id of the sender that sent the message
                    message_id       integer    id of the received message
                    clear_message    SegData    clear message that was received from the record layer
            Output: -
        '''
        # monitor
        self._monitor_simple(sender_id, message_id, clear_message)
        
        # forward
        return [message_id, clear_message]

    
    def _monitor_simple(self, sender_id, message_id, clear_message):
        ''' monitors messages that arrived from the application
            protocol
            
            Input:  sender_id        string     id of the sender that sent the message
                    message_id       integer    id of the received message
                    clear_message    SegData    clear message that was received from the record layer
            Output: -
        '''
        # information
        uid = uuid.uuid4().hex
        now = self.sim_env.now
        size = len(clear_message)
        monitor_tag = MonitorTags.CP_RECEIVE_SIMPLE_MESSAGE        
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, now, sender_id, message_id, clear_message, size, message_id, uid))

class ObjectMap(Singleton):
    ''' this class saves objects that are identical. E.g. if 10 ECUs the same message 
        this message will be only saved once and referenced then '''
    
    def __init__(self):
        self._object_map = {}
        self._mac_map = {}
        self._sym_key_map = {}
        self._size = 0
    
    def request(self, potential_input):
        ''' once a object with a certain id is requested the object 
            checks if the given potential input is already existing 
            If this is the case it will return the requested object
            
            Input:    potential_input    dict/list    input that is requested
            Output:   output             dict/list     the requested list or dictionary
        '''
        if str(potential_input) in self._object_map.keys():
            return self._object_map[str(potential_input)]
        else:
            self._object_map[str(potential_input)] = Wrapped(potential_input)
            picklestring = pickle.dumps(Wrapped(potential_input))
            self._size += len(picklestring)
#             print("New element: keys: %s   size: %s Megabyte" % (len(self._object_map.keys()), self._size / 1000000))
            return self._object_map[str(potential_input)]
    
    def request_mac_key(self, mac_key):
        ''' once a mac_key is requested the object 
            checks if a similar one is already existing 
            If this is the case it will return the similar one
            
            Input:    suite            TLSSecurityParameter    input that is requested
            Output:   output             dict/list         the requested list or dictionary
        '''
        
        ky = str([mac_key.valid_alg, mac_key.valid_key_len, mac_key.id ])
        
        if ky in self._mac_map:
            del mac_key
            return self._mac_map[ky]
         
        self._mac_map[ky] = mac_key
        return mac_key
    
    def request_sym_key(self, sym_key):
        ''' once a sym_key is requested the object 
            checks if a similar one is already existing 
            If this is the case it will return the similar one
            
            Input:    suite            TLSSecurityParameter    input that is requested
            Output:   output             dict/list         the requested list or dictionary
        '''
        
        ky = str([sym_key.valid_alg, sym_key.valid_key_len, sym_key.id, sym_key.valid_alg_mode])
        
        if ky in self._sym_key_map:
            del sym_key
            return self._sym_key_map[ky]
         
        self._sym_key_map[ky] = sym_key
        return sym_key
    
    def remove(self, innput):
        ''' removes the object from memory'''
        try:
            if str(innput) in self._object_map.keys():print("FOUND!")
            del self._object_map[str(innput)]
            self._object_map.pop(str(innput), None)
            print("Removed")
        except:
            pass
        
    def remove_unreferenced(self):
        rem_kys = []
        for ky in self._object_map.keys():
            nr = sys.getrefcount(self._object_map[ky])
            if nr == 2:
                rem_kys.append(ky)
                
        for k in rem_kys:
            self._object_map.pop(ky, None)
            
    
        
class Wrapped(object):
    
    def __init__(self, ctnt):
        self._content = ctnt
        
    def set(self, cntnt):
        self._content = cntnt
        
    def get(self):
        return self._content
        
