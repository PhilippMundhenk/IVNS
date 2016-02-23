import simpy
import random
from components.base.ecu.software.abst_comm_layers import AbstractCommModule
from components.base.ecu.software.impl_physical_layers import StdPhysicalLayer
from components.base.ecu.software.impl_datalink_layers import  RapidDatalinkLayer, \
    StdDatalinkLayer
from components.base.ecu.software.impl_transport_layers import FakeSegmentTransportLayer
from components.base.message.abst_bus_message import SegData
from components.security.encryption import encryption_tools
from components.security.encryption.public_key_manager import PublicKeyManager
from components.security.encryption.encryption_tools import HashedMessage, EncryptionSize
from config import project_registration as proj, can_registration
from config import timing_registration as time
from tools.ecu_logging import ECULogger as L, try_ex
from tools.general import General as G, RefList, General
from io_processing.surveillance_handler import MonitorInput, MonitorTags
import logging
import uuid
from config.specification_set import GeneralSpecPreset

class SecureCommModule(AbstractCommModule):
    ''' This class implements a secure communication
        module, that enables secure communication between
        several ECUs via the security module connected to it'''
    
    def __init__(self, sim_env, ecu_id):
        ''' Constructor
            
            Input:  ecu_id         string                   id of the corresponding AbstractECU
                    sim_env        simpy.Environment        environment of this component
            Output:  -
        '''
        AbstractCommModule.__init__(self, sim_env)

        # initialize
        self._ecu_id = ecu_id
        self._stream_queue = {}
        self._stream_active = {}
        self._last_req_stamp = {}
        self._stream_max_queue_length = 200
        self._jitter_in = 1
        self.monitor_list = RefList()
        self._stream_done = {}
        self.last_decryption_to = 0
        self.skip_decryption_to = False
        
        # layers
        self._init_layers(sim_env, self.MessageClass)

        # project parameters
        self._ecu_sym_enc_alg = proj.SCCM_ECU_SYM_KEY_ENC_ALG      
        self._ecu_sym_enc_keyl = proj.SCCM_ECU_SYM_KEY_ENC_KEY_LEN 
        self._ecu_sym_enc_alg_mode = proj.SCCM_ECU_SYM_KEY_ENC_ALG_MODE
        self._assym_enc_alg = proj.SCCM_ECU_PUB_ENC_ALG
        self._assym_enc_alg_option = proj.SCCM_ECU_PUB_ENC_ALG_OPTION
        self._assym_enc_key_len = proj.SCCM_ECU_PUB_ENC_KEY_LEN
        self.SCCM_MAX_WAIT_TIMEOUT = proj.SCCM_MAX_WAIT_TIMEOUT
                
        # authenticator/authorizer
        self._init_authentors(sim_env, self.MessageClass, ecu_id, self._ecu_sym_enc_alg, self._ecu_sym_enc_keyl, \
                              self._assym_enc_alg, self._assym_enc_alg_option, self._assym_enc_key_len, self._ecu_sym_enc_alg_mode)   

    
    def receive_msg(self):
        ''' receives messages from the transport layer and
            processes the stream authorization and ecu authentication
            mechanism, ensuring a secure communication
            
            Input:     -
            Output:    -
        '''
        
        # active authentication
        if self.authenticator.active:

            while True:
                
                # receive message
                [message_id, message_data] = yield self.sim_env.process(self.transp_lay.receive_msg())      
                
                # received ecu authentication message
                if self._is_auth_msg(message_id): yield self.sim_env.process(self.authenticator.process(message_id, message_data))  
                    
                # received stream authorization message
                elif self._is_authori_msg(message_id):
                    if not self.authenticator.confirmed: return G().val_log_info([None, None], 125, self.ecu_id)
                    yield self.sim_env.process(self.authorizer.process(message_id, message_data))  

                # received simple message
                else:
                    # decryption
                    time_val, msg_clear = self._simple_decryption_timeout_message(message_id, message_data)
                    self.last_decryption_to = time_val
                    if not time_val: continue
                    if not self.skip_decryption_to: yield self.sim_env.timeout(time_val)
                                        
                    # decryption failed
                    if msg_clear == None: continue       
                    
                    # authentication incomplete           
                    if not self.authenticator.confirmed: return G().val_log_info([None, None], 125, self.ecu_id)     
                    
                    # result    
                    return [message_id, msg_clear]
        else:
            return [message_id, message_data] 

    
    def request_grant(self, sender_id, message_id, message):
        ''' this method starts the request process. It is stuck until 
            this stream was authorized or denied. Request messages are
            sent in a defined interval.
        
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
            Output: bool         boolean       True if the stream was granted, False when deny message received 
        '''
        # already authorized: return true
        if self.authorizer.stream_authorized(message_id): return True
        
        # else start authorization
        # start a process that waits for granting if no grant received in a certain timeframe
        # resend the request message
        
        # start this process in the defined intervals
        done = False
        self._stream_done[message_id] = False
        
        while not done:            
            
            # second process requesting
            if not General().disable_permanent_request:
                self.sim_env.process(self._permanent_request(sender_id, message_id, message))
            
            # send first message
            success = yield self.sim_env.process(self.send_msg(sender_id, message_id, message))
            
            # send the request message
            if self.authorizer.stream_authorized(message_id) or success: 
                self._stream_done[message_id] = True
                return True
            
            yield self.sim_env.timeout(self.authorizer.SSMA_STREAM_MIN_INTERVAL)
            
    def request_timeout(self, sender_id, message_id, message, passed_encryption_time=False):
        ''' this method returns the timeout that will be necessary for the 
            encryption of the message
            
            Input:  sender_id        string        id of the ecu that wants to send the message
                    message_id       integer       identifier of the message that is to be sent
                    message          object        message that will be sent
            Output: encryption_time  float         time to encrypt the message
        '''
        
        # encrypted message
        encryption_time, encrypted_message = self._simple_encryption_message_time(message_id, sender_id, message, passed_encryption_time)
        
        return encryption_time
            
    def last_decryption_time(self):
        ''' if the decryption time was skipped this message will return the time 
            skipped
            
            Input: -
            Output: skipped_time     float        time that was skipped
        '''
        return 0
            
    def _permanent_request(self, sender_id, message_id, message):
        ''' sends a request message in fixed time intervals until it is interrupted
        
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
            Output: -
        '''
        while True:
            return
            yield self.sim_env.timeout(self.authorizer.SSMA_STREAM_MIN_INTERVAL)
            
            if not self._stream_done[message_id]:
                # send only stream request nothing else                
                encryption_time, request_message = self.authorizer._stream_request_time_message(message_id)
                yield self.sim_env.timeout(encryption_time)  # evtl. remove if assume encrypted earlier
                yield self.sim_env.process(self.transp_lay.send_msg(self._ecu_id, can_registration.CAN_STR_AUTH_INIT_MSG_STR, request_message)) 

            else:
                return
            
    
    def send_msg(self, sender_id, message_id, message, skip_timeout=False):
        ''' sends a message to the lower layers. Applies stream authorization
            to ensure a secure communication 
            
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
            Output: -
        '''
        
        # logging
        L().log(100, self.sim_env.now, self._ecu_id, message_id, message)
                
        # message authorized
        if self.authorizer.stream_authorized(message_id):
            yield self.sim_env.process(self._handle_stream_authorized(sender_id, message_id, message, skip_timeout=skip_timeout))

        # message not authorized
        else: 
            success = yield self.sim_env.process(self._handle_not_authorized(sender_id, message_id, message))
            return success
    
    def set_authenticated(self, authenticated):
        ''' this method can be used to set the ecu authenticated
            before the start of the simulation
            
            Input:    authenticated    boolean    true if this ecu is already authenticated
            Output:    -
        '''
        self.authenticator.confirmed = authenticated
      
          
    def _check_time_queue(self, sender_id, message_id, message):
        ''' this method checks if the current stream is continuing. If the
            hold mechanism is enabled this method adds the incoming messages
            to the queue that will be used to send the messages after a successful    
            authentication. It will return false when the stream request is still
            going on.
            if hold was not defined the incoming messages are dropped. and false will
            be returned
            True will be returned when the next message is allowed to be sent
            
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
            Output: bool         boolean       true if the authentication/authorization is over and the next message can be sent
        '''
        
        # time passed since last message
        passed_time = self.sim_env.now - self._last_req_stamp[message_id]  
        
        # queue else retry
        if passed_time < self.authorizer.SSMA_STREAM_MIN_INTERVAL: 
            
            
            # if hold on: Check if stream request is going on, then queue  and G().dictlist_exists(self._stream_queue, message_id)
            if self.authorizer.SSMA_STREAM_HOLD and G().dict_exists(self._stream_active, message_id):            
                G().force_add_dict_list(self._stream_queue, message_id, [sender_id, message_id, message], self._stream_max_queue_length)  # add to queue, until max length, remove last
                return False
            
            # if drop is on within this time frame simply continue
            if not self.authorizer.SSMA_STREAM_HOLD:
                return False
        
        return True
    
    
    def _handle_not_authorized(self, sender_id, message_id, message):
        ''' If the stream was not authorized yet, this method will start the 
            authorization process. At the same time a second process is started.
            This process is interrupting the authorization process after a certain
            timeout time has passed, thus ensuring that this ECU will not be stuck 
        
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
            Output: -
        '''

        # confirmation check
        if not self.authenticator.confirmed: return G().val_log_info(False, 107)
        
        # synchronizer
        sync = simpy.Store(self.sim_env, capacity=1); L().log(101, message_id)
        
        # Stream is active
        if not self._stream_is_active(sender_id, message_id, message): return
        
        # authorization/timeout process
        try_auth_pro = self.sim_env.process(self._start_inter_authorization(message_id, sync))
        timeout_proc = self.sim_env.process(self._timeout_after_max(self.SCCM_MAX_WAIT_TIMEOUT, sync, message_id))
        timed_out = yield sync.get()

        # send current message
        success = yield self.sim_env.process(self._handle_timeout(timeout_proc, try_auth_pro, timed_out, sender_id, message_id, message))
    
        # send all messages in the queue for that stream
        if self.authorizer.SSMA_STREAM_HOLD and G().dictlist_exists(self._stream_queue, message_id) and success:
           
            while True:                
                # process queue
                for msg in self._stream_queue[message_id]:
                    yield self.sim_env.process(self._handle_stream_authorized(msg[0], msg[1], msg[2], True))
                    self._stream_queue[message_id].remove(msg)
                    
                # if queue empty continue   
                if not self._stream_queue[message_id]: break  
            
        # stream is not active anymore            
        self._stream_active[message_id] = False 
        
        return success
    
    
    def _handle_stream_authorized(self, sender_id, message_id, message, skiphold=False, skip_timeout=False):
        ''' If the stream was authorized then encrypt the message with the 
            corresponding session key and send it to lower layers 
            
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
                    skiphold     boolean       true if the first condition is to be skipped
            Output: - 
        '''
        
        # if hold on: Check if queue is not empty, then queue
        if self.authorizer.SSMA_STREAM_HOLD and G().dictlist_exists(self._stream_queue, message_id) and skiphold == False:          
            G().force_add_dict_list(self._stream_queue, message_id, [sender_id, message_id, message], self._stream_max_queue_length)  # add to queue, until max length, remove last
            return
        
        # guarantee one process at a time
        yield self.authorizer._busy.get()
        
        # encrypted message
        encryption_time, encrypted_message = self._simple_encryption_message_time(message_id, sender_id, message, skip_timeout=skip_timeout)
                
        # timeout encryption time
        if not skip_timeout:  yield self.sim_env.timeout(encryption_time)
        
        # kind of process synchronization
        self.authorizer._busy.put(True)
        
        # send message
        yield  self.sim_env.process(self.authorizer.transp_lay.send_msg(sender_id, message_id, encrypted_message))  
        
    def _authorizer_timed_out(self, value, timeout_proc, message_id):
        ''' if the sender does not receive an answer after a certain amount
            of time this method interrupts the sending process. If value
            is none a timeout happened
        
            Input:    value    object    if none timeout happened
            Output:   bool     boolean   True if interrupted 
        '''
        # timed out
        if value == None: 
            # interrupt process
            timeout_proc.interrupt()
            self.authorizer.sender[message_id] = False
            L().log(103, self._ecu_id, message_id)
            return True
        
        if not value:
            timeout_proc.interrupt()
            self.authorizer.sender[message_id] = False
            L().log(104, self._ecu_id, message_id)
        
        # no timeout
        return False
        
    
    def _handle_timeout(self, timeout_proc, try_auth_proc, timed_out, sender_id, message_id, message):
        ''' checks the result of the stream authorization attempt. If timed_out is None the message is not 
            sent because the authorization process was not successful. If it is False the authorization 
            process is successful and the message is sent. If it is True the stream authorization process
            is aborted and again no message is sent 
            
            returns True if successful and False otherwise'''
        
        # timed out
        if self._authorizer_timed_out(timed_out, timeout_proc, message_id):  return False

        # send simple message
        if not timed_out:            
            
            # encrypted message
            encryption_time, encrypted_message = self._simple_encryption_message_time(message_id, sender_id, message)
                    
            # timeout encryption time
            yield self.sim_env.timeout(encryption_time)
            
            # send message
            yield  self.sim_env.process(self.authorizer.transp_lay.send_msg(sender_id, message_id, encrypted_message))    
            
            return True
        else:
            try_auth_proc.interrupt()
            self.authorizer.sender[message_id] = False
            L().log(105, self._ecu_id, message_id)
            return False
        
    
    def _init_authentors(self, sim_env, MessageClass, ecu_id, symmetric_enc_algorithm, symmetric_enc_key_length, assymmetric_enc_algorithm, assymmetric_enc_alg_option, assymmetric_enc_key_length, symmetric_enc_algorithm_mode):
        ''' Sets the authentication core Objects
        
            Input:  sim_env                        simpy.Environment        environment of this component                    
                    MessageClass                   AbstractBusMessage       class of the messages  how they are sent on the CAN Bus
                    ecu_id                         string                   id of the corresponding AbstractECU
                    symmetric_enc_algorithm        SymAuthMechEnum          symmetric algorithm used for the ECU communication with the security module (not session key)
                    symmetric_enc_key_length       AuKeyLengthEnum          symmetric algorithm key length used for the ECU communication with the security module (not session key)
                    symmetric_enc_algorithm_mode   SymAuthMechEnum          symmetric algorithm mode used for the ECU communication with the security module (not session key)
                    assymmetric_enc_algorithm      AsymAuthMechEnum         asymmetric algorithm used to exchange initial information between ECU and security module
                    assymmetric_enc_alg_option     number/string/...        asymmetric algorithm option used to exchange initial information between ECU and security module
                    assymmetric_enc_key_length     AuKeyLengthEnum          asymmetric algorithm key length used to exchange initial information between ECU and security module

            Output:  -    
        '''        
        self.authenticator = StdAuthentor(sim_env, self.transp_lay, MessageClass, ecu_id, symmetric_enc_algorithm, symmetric_enc_key_length, assymmetric_enc_algorithm, \
                                          assymmetric_enc_alg_option, assymmetric_enc_key_length, symmetric_enc_algorithm_mode, monitor_list=self.monitor_list, jitter=self._jitter)    
        self.authorizer = StdAuthorize(sim_env, self.transp_lay, self.authenticator, monitor_list=self.monitor_list, jitter=self._jitter)        
        self.authenticator.activate()
    
    
    def _init_layers(self, sim_env, MessageClass):
        ''' Initializes the software layers 
        
            Input:  sim_env                        simpy.Environment        environment of this component                    
                    MessageClass                   AbstractBusMessage       class of the messages  how they are sent on the CAN Bus
            Output: -
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
        
    
    def _is_auth_msg(self, message_id):
        ''' true if the message is a ECU Authentication Message 
            
            Input:     message_id    integer    id of the incoming message
            Output:    bool          boolean    true if this message is an authentication message
        '''
        try:
            if message_id in can_registration.ECU_AUTH_MESSAGES:
                return True
        except:
            pass
        return False
    
    
    def _is_authori_msg(self, message_id):
        ''' true if the message is a Stream Authorization Message 
        
            Input:     message_id    integer    id of the incoming message
            Output:    bool          boolean    true if this message is an authorization message
        '''
        try:
            if message_id in can_registration.STREAM_AUTH_MESSAGES:
                return True
        except:
            pass
        return False
    
    
    def _simple_decryption_timeout_message(self, stream_id, message_data):
        ''' this method returns the time it takes to 
            decrypt a simple message with the session key.
            Above that it returns the decrypted message.
            If no session key is available for this stream
            False is returned else the time value is returned      
            
            Input:   stream_id        integer            id of the incoming message
                     message_data     EncryptedMessage   data received
            Output:  time_val         float              time it takes to decrypt the incoming message
                     clear_message    object             decrypted message
        '''
        
        # extract information    
        try:    
            algorithm = self.authorizer.session_keys[stream_id].valid_alg
            algorithm_mode = self.authorizer.session_keys[stream_id].valid_alg_mode
            key_length = self.authorizer.session_keys[stream_id].valid_key_len
        except:
            return False, None
        
        # check session key
        if stream_id not in self.authorizer.session_keys:
            logging.info("ECU %s: Time %s:  No Session key for Message Stream %s" % (self._ecu_id, self.sim_env.now, stream_id))
            return False, False
                            
        # decryption time
        time_val = time.call(self.authorizer.SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY, algorithm, key_length, len(message_data), algorithm_mode) * self._jitter
        
        # clear message
        clear_message = self.authorizer.receive_decrypt(stream_id, message_data, time_val)
        
        
        # log
        G().to_t(self.sim_env, time_val , 'SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY', self.authorizer.__class__.__name__, self.authenticator._ecu_id)        
        
        return time_val, clear_message
    
    
    def _simple_encryption_message_time(self, message_id, sender_id, message, passed_encryption_time=False, skip_timeout=False):
        ''' this message returns the time needed to encrypt a 
            simple message and the encrypted message
            
            
            Input:  sender_id            string            id of the ecu that wants to send the message
                    message_id           integer           identifier of the message that is to be sent
                    message              object            message that will be sent
            Output: encryption_time      float             time to encrypt the message that needs to be sent
                    encrypted_message    EncryptedMessage  the message that will be sent after encryption  
        '''
        
        # information
        algorithm = self.authorizer.session_keys[message_id].valid_alg
        key_length = self.authorizer.session_keys[message_id].valid_key_len
        algorithm_mode = self.authorizer.session_keys[message_id].valid_alg_mode
        
        # log
        L().log(102, self.sim_env.now, self._ecu_id, message_id)
        
        # encryption time
        encryption_time = time.call(self.authorizer.SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY, algorithm, key_length, len(message), algorithm_mode) 
        encryption_time *= self._jitter
        G().to_t(self.sim_env, encryption_time , 'SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY', self.__class__.__name__, self.authenticator._ecu_id)
        
        # encrypted message
        sender_id, message_id, encrypted_message = self.authorizer.send_enyrypted(sender_id, message_id, message, encryption_time, passed_encryption_time, skip_timeout)
        
        return encryption_time, encrypted_message
    
    
    def _start_inter_authorization(self, message_id, sync):
        ''' Starts the authorization process. Puts False into the sync object
            if it was successful and None if it was not. This process is interrupted
            by the timeout process running in parallel if this sender has not received
            an answer to his request after a defined time
            
            Input:   message_id    integer        identifierr of the message incoming
                     sync          simpy.Store    communication between this process and the interruption process
            Output:  -
        '''
        try:
            # try initialize
            result = yield self.sim_env.process(self.authorizer.init_msg_stream(message_id))
            
            # initialization failed
            if not result: sync.put(None)
            
            # initialization successful
            else: sync.put(False)
            
        except simpy.Interrupt:
            pass
          
    
    def _stream_is_active(self, sender_id, message_id, message): 
        ''' this method is true if the stream authorization is still going on.
            Moreover it notes the last time this stream was requested and sets
            the activity true
        
            Input:  sender_id    string        id of the ecu that wants to send the message
                    message_id   integer       identifier of the message that is to be sent
                    message      object        message that will be sent
            Output: bool         boolean       true if the stream authorization is still going on 
        '''
        
        # authorization over
        if G().dict_exists(self._last_req_stamp, message_id):
            if not self._check_time_queue(sender_id, message_id, message): 
                return False    
        
        # note last time
        self._stream_active[message_id] = True
        self._last_req_stamp[message_id] = self.sim_env.now
        
        return True
           
     
    def _timeout_after_max(self, time, sync, message_id):
        ''' Waits for a certain amount of time and puts True into
            the sync object, which will lead to an abortion of the
            authorization process. If the sending process was successful
            it will interrupt this process first
        
            Input:  time     float        timeout time. So the maximum time the sender waits for a response to his
                                          stream request
                    sync    simpy.Store   communication between this process and the sending process
            Output:  -            
        '''
        try:
            # log
            G().to_t(self.sim_env, time , 't_req_msg_max_timeout', self.__class__.__name__, self._ecu_id)
            
            # wait 
            yield self.sim_env.timeout(time)            
            
            # interrupt the sender
            sync.put(True)
            L().log(106, self._ecu_id, message_id)

        except simpy.Interrupt:
            pass
    
    @property
    
    def assym_enc_alg_option(self):
        return self._assym_enc_alg_option

    @assym_enc_alg_option.setter
    
    def assym_enc_alg_option(self, value):
        self._assym_enc_alg_option = value
        self.authenticator.priv_key, self.authenticator.pub_key = encryption_tools.asy_get_key_pair(self._assym_enc_alg, self._assym_enc_key_len, self._assym_enc_alg_option)
        PublicKeyManager().add_key(self._ecu_id, self.authenticator.pub_key) 
        
        self.authenticator.SCCM_ECU_PUB_ENC_ALG_OPTION = value        
    
    @property
    
    def assym_enc_alg(self):
        return self._assym_enc_alg

    @assym_enc_alg.setter
    
    def assym_enc_alg(self, value):
        self._assym_enc_alg = value
        self.authenticator.priv_key, self.authenticator.pub_key = encryption_tools.asy_get_key_pair(self._assym_enc_alg, self._assym_enc_key_len)
        PublicKeyManager().add_key(self._ecu_id, self.authenticator.pub_key) 
        
        self.authenticator.SCCM_ECU_PUB_ENC_ALG = value        
          
    @property
    
    def assym_enc_key_len(self):
        return self._assym_enc_key_len

    @assym_enc_key_len.setter
    
    def assym_enc_key_len(self, value):
        self._assym_enc_key_len = value            
        self.authenticator.priv_key.valid_key_len = self._assym_enc_key_len
        self.authenticator.pub_key.valid_key_len = self._assym_enc_key_len        
        self.authenticator.SCCM_ECU_PUB_ENC_KEY_LEN = value
       
    @property
    
    def ecu_sym_enc_alg_mode(self):
        return self._ecu_sym_enc_alg_mode 
    
    @ecu_sym_enc_alg_mode.setter
    
    def ecu_sym_enc_alg_mode(self, value):
        self._ecu_sym_enc_alg_mode = value  
           
        self.authenticator.sym_key = encryption_tools.sym_get_key(self._ecu_sym_enc_alg, self._ecu_sym_enc_keyl, self._ecu_sym_enc_alg_mode)
        self.authenticator.SCCM_ECU_SYM_KEY_ENC_ALG_MODE = value    
        self.authorizer.SCCM_ECU_SYM_KEY_ENC_ALG_MODE = value
        self.authenticator.sym_key.valid_alg_mode = value 
        
        # inform security module
        if self.authenticator.confirmed:
            self.changed_sym_key.emit([self._ecu_id, self.authenticator.sym_key])
        
    @property
    
    def _jitter(self):
        return self._jitter_in
    
    @_jitter.setter
    
    def _jitter(self, val):
        try:
            self.authenticator._jitter = val
            self.authorizer._jitter = val
        except:
            pass
        self._jitter_in = val
            
    @property
    
    def ecu_sym_enc_alg(self):
        return self._ecu_sym_enc_alg 
    
    @ecu_sym_enc_alg.setter
    
    def ecu_sym_enc_alg(self, value):
        self._ecu_sym_enc_alg = value        
        self.authenticator.sym_key = encryption_tools.sym_get_key(self._ecu_sym_enc_alg, self._ecu_sym_enc_keyl, self._ecu_sym_enc_alg_mode)
        self.authenticator.SCCM_ECU_SYM_KEY_ENC_ALG = value    
        self.authorizer.SCCM_ECU_SYM_KEY_ENC_ALG = value
        
        # inform security module
        if self.authenticator.confirmed:
            self.changed_sym_key.emit([self._ecu_id, self.authenticator.sym_key])
             
    @property
    
    def ecu_sym_enc_keyl(self):
        return self._ecu_sym_enc_keyl
    
    @ecu_sym_enc_keyl.setter
    
    def ecu_sym_enc_keyl(self, value):
        self._ecu_sym_enc_keyl = value        
        self.authenticator.sym_key = encryption_tools.sym_get_key(self._ecu_sym_enc_alg, self._ecu_sym_enc_keyl, self._ecu_sym_enc_alg_mode)
        self.authenticator.SCCM_ECU_SYM_KEY_ENC_KEY_LEN = value        
        self.authorizer.SCCM_ECU_SYM_KEY_ENC_KEY_LEN = value
        
        # inform security module
        if self.authenticator.confirmed:
            self.changed_sym_key.emit([self._ecu_id, self.authenticator.sym_key])
    
    @property
    
    def ecu_id(self):
        return self._ecu_id
               
    @ecu_id.setter    
    
    def ecu_id(self, value):
        self._ecu_id = value          
        self.authenticator._ecu_id = value
        
    @property
    
    def sec_mod_id(self):
        return self._sec_mod_id
    
    @sec_mod_id.setter
    
    def sec_mod_id(self, value):
        self._sec_mod_id = value
        self.authenticator.sec_id = value

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

class StdAuthorize(object):
    '''
    This class implements the stream authorization process. It receives and
    sends messages based on the proposed security scheme
    '''
    
    def __init__(self, sim_env, transport_layer, ecu_authentor, monitor_list=[], jitter=1):
        ''' Constructor
        
            Input:  sim_env            simpy.Environment         environment of this component
                    transport_layer    AbstractTransportLayer    transport layer connected to this security module
                    ecu_authentor      StdAuthentor              ECU Authentication handler
                    monitor_list       RefList                   list for the monitor input
                    jitter             float                     random value multiplied on each timeout
            Output:  -    
        '''        
        # passed objects
        self.authento = ecu_authentor        
        self.sim_env = sim_env        
        self.transp_lay = transport_layer
        self.monitor_list = monitor_list
        self._jitter = jitter
        self._busy = simpy.Store(self.sim_env, capacity=1)  # while the communication module is busy other parties wait for it
        self._busy.put(True)
                
        # initial objects
        self._init_values()

        # timing parameter
        self.SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY = time.SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY
        self.SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY = time.SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY
        self.SCCM_STREAM_ENC_REQ_MSG = time.SCCM_STREAM_ENC_REQ_MSG
        self.SCCM_STREAM_DEC_DENY_MSG = time.SCCM_STREAM_DEC_DENY_MSG
        self.SCCM_STREAM_DEC_GRANT_MSG = time.SCCM_STREAM_DEC_GRANT_MSG

        # project parameter
        self.SCCM_ECU_REQ_MSG_SIZE = proj.SCCM_ECU_REQ_MSG_SIZE
        self.SSMA_SIZE_REQ_MSG_CONTENT = proj.SSMA_SIZE_REQ_MSG_CONTENT
        self.SSMA_SIZE_REQ_MSG_CIPHER = proj.SSMA_SIZE_REQ_MSG_CIPHER 
        self.SSMA_GRANT_MSG_CIPHER_SIZE = proj.SSMA_GRANT_MSG_CIPHER_SIZE

        self.SCCM_ECU_SYM_KEY_ENC_ALG = proj.SCCM_ECU_SYM_KEY_ENC_ALG
        self.SCCM_ECU_SYM_KEY_ENC_ALG_MODE = proj.SCCM_ECU_SYM_KEY_ENC_ALG_MODE
        self.SCCM_ECU_SYM_KEY_ENC_KEY_LEN = proj.SCCM_ECU_SYM_KEY_ENC_KEY_LEN
        self.SSMA_GRANT_MSG_CT_SIZE = proj.SSMA_GRANT_MSG_CT_SIZE
        
        self.SSMA_STREAM_HOLD = proj.SSMA_STREAM_HOLD
        self.SSMA_STREAM_MIN_INTERVAL = proj.SSMA_STREAM_MIN_INTERVAL
        
    def init_msg_stream(self, stream_id):
        ''' this method will start the sending process of the 
            request message for the message with the passed
            stream_id 
            
            Input:   stream_id    integer    message stream this ecu tries to get granted by the security module
            Output:  bool         boolean    true if the ecu received a response                    
        '''
        
        # reset
        self._reset_init_msg_stream(stream_id)
        
        # check confirmation
        if not self.authento.confirmed: return G().val_log_info(False, 107)
        
        # one input at a time is allowed to do that
        yield self._busy.get()
        
        # create message
        encryption_time, request_message = self._stream_request_time_message(stream_id)
             
        # wait encryption time
        yield self.sim_env.timeout(encryption_time)
        
        # send message
        yield self.sim_env.process(self.transp_lay.send_msg(self.authento._ecu_id, can_registration.CAN_STR_AUTH_INIT_MSG_STR, request_message)) 
        
        # next process can send
        self._busy.put(True)

        # log 
        L().log(108, self.authento._ecu_id, stream_id)   
        
        # new synchronizer for this stream
        self.sync[stream_id] = simpy.Store(self.sim_env, capacity=1)
        self.sync_message[stream_id] = simpy.Store(self.sim_env, capacity=1)
        
        val = yield self.sync[stream_id].get()
                        
        # stream successful
        if not val: return False        
        return True
    
    
    def process(self, msg_id, msg_data):
        ''' this method receives the messages from the communication module
            and processes it
            
            Input:    message_id        integer    id of the message that was received
                      message_data      object     message that was received
            Output:   - 
        '''
        
        # grant message
        if can_registration.CAN_STR_AUTH_GRANT_MSG == msg_id: 
            time_val = self._time_decrypt_grant_message()    
            yield self.sim_env.timeout(time_val)        
            yield self.sim_env.process(self._handle_grant_msg(msg_id, msg_data, time_val))
            
        # deny message
        if can_registration.CAN_STR_AUTH_DENY_MSG == msg_id:       
            yield self.sim_env.process(self._handle_deny_msg(msg_id, msg_data))   
    
    
    def receive_decrypt(self, message_id, message_data, decryption_time):
        ''' this method receives simple messages and decrypts 
            them. Then the values are returned
            
            Input:    message_id        integer        id of the incoming message
                      message_data      SegData        content of the incoming message
                      decryption_time   float          time the decryption of this message took
            Output:   clear_message     object         message that was decrypted
        '''
        try:
            # log decryption            
            uid = self._log_simple_decryption_start(message_data, message_id)
                        
            # decryption_time passed
            clear_message = encryption_tools.sym_decrypt(message_data.get(), self.session_keys[message_id], self.sim_env.now + decryption_time)
            G().note_sz(str([self.authento._ecu_id, 'LAST_SIMP_MSG_UNENC_REC_SIZE']), len(clear_message)) 
            
            # log decryption   
            self._log_simple_decryption_end(message_id, message_data, decryption_time, clear_message, uid)
            
            # notify other
            self.sync_message[message_id].put(True)
        except KeyError:
            pass            
        except:
            return G().val_log_info(None, 109, self.authento._ecu_id, message_id)
           
        return clear_message

        
    def send_enyrypted(self, sender_id, stream_id, message, encryption_time, passed_encryption_time=False, skip_timeout=False):
        ''' this method creates the message that is send by encrypting
            it with the right session key
            
            Input:  sender_id         string             id of the ecu that wants to send the message
                    stream_id         integer            id of the message to be sent
                    message           object             message that is to be sent
                    encryption_time   float              time it takes to encrypt the message
            Output: sender_id         string             id of the ecu that wants to send the message
                    stream_id         integer            id of the message to be sent    
                    encrypted_message EncryptedMessage   message that was encrypted and that is to be sent 
        '''
        # session key
        session_key, uid = self._session_key_simple_encryption(stream_id, message, encryption_time, passed_encryption_time, skip_timeout)       
        
        # enc_time passed
        encrypted_message, encrypted_size = self._encryption_size_message_simple_transmit(stream_id, message, encryption_time, session_key, uid, passed_encryption_time, skip_timeout)  # @UnusedVariable
        
        # result
        return sender_id, stream_id, encrypted_message
   
    
    def stream_authorized(self, stream_id):
        ''' returns True if there is a valid session key 
            for this stream
        
            Input:    stream_id    integer    stream that is to be checked                            
            Output:   bool         boolean    true if a valid session key exists
        '''
        # check session key
        if stream_id not in self.session_keys: return G().val_log_info(False, 110, self.authento._ecu_id, stream_id)
        
        # key valid
        if self.session_keys[stream_id].valid_till < self.sim_env.now:
            return G().val_log_info(False, 111, self.authento._ecu_id, stream_id, self.session_keys[stream_id].valid_till)
                
        # Stream authorized
        return G().val_log_info(True, 112, self.authento._ecu_id, stream_id)
    
    
    def _clear_request_message(self, stream_id):
        ''' this method returns the clear message of
            the request message
            
            Input:     stream_id        integer    identifier of the requested stream
            Output:    clear_message    list        clear request message
                       uid              uuid        unique id of message
                       req_ecu_id       string      id of the requesting ecu  
        '''
        # log
        uid = uuid.uuid4()
        L().log(113, self.authento._ecu_id, stream_id)
        
        # extract
        stream_id, req_ecu_id, timestamp, self.nonce = stream_id, self.authento._ecu_id, self.sim_env.now, self._get_nonce()    
        
        # create message
        clear_message = [req_ecu_id, stream_id, self.nonce, timestamp]; 
        
        # monitor
        monitor_tag = MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE
        ecu_id = self.authento._ecu_id
        asc_id = self.authento.sec_id
        msg_id = can_registration.CAN_STR_AUTH_INIT_MSG_STR
        size = self.SSMA_SIZE_REQ_MSG_CONTENT
        L().log(126, self.sim_env.now, ecu_id, clear_message, size)
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, self.sim_env.now, asc_id, msg_id, clear_message, size, stream_id, uid))
        
        # not size
        G().note_sz(str([self.authento._ecu_id, 'SSMA_SIZE_REQ_MSG_CONTENT']), self.SSMA_SIZE_REQ_MSG_CONTENT)   
        
        return clear_message, uid, req_ecu_id
    
    
    def _create_stream_request_message(self, stream_id, encryption_time):
        ''' create a stream request message for a given stream_id
        
            Input:    stream_id        integer    id of the stream to be requested
                      encryption_time  float      time it takes to encrypt the stream request
            Output:   message          SegData    stream request message
        '''
        
        # clear text
        clear_message, uid, req_ecu_id = self._clear_request_message(stream_id)
        
        # encrypt text (encryption_time passed)         
        encrypted_message = encryption_tools.sym_encrypt(clear_message, self.authento.sym_key)
        msg_to_send = [req_ecu_id, encrypted_message] 
        
        # size request message        
        sending_size = self._stream_request_cipher_size(encryption_time, encrypted_message)
        
        # sendable message
        message = SegData(msg_to_send, sending_size)
        message.unique_id = uid
        
        # monitor
        self._log_stream_request_create(encryption_time, msg_to_send, sending_size, stream_id, message)
        
        # return
        return message
    
    
    def _deny_message_size(self, message_data):
        ''' this message returns the size of the deny message and
            logs the sizes before and after encryption as well as the
            content
            
            Input:      message_data    SegData    incoming deny message
            Output:     cipher_size     float      size of the deny message encrypted
        '''
        
        # extract information
        algorithm = self.authento.sym_key.valid_alg
        key_length = self.authento.sym_key.valid_key_len
        
        # log
        G().note_sz(str([self.authento._ecu_id, 'SSMA_DENY_MSG_REC_SIZE']), len(message_data))   
        
        # size 
        cipher_size = G().call_or_const(self.SSMA_GRANT_MSG_CIPHER_SIZE, self.SSMA_GRANT_MSG_CT_SIZE, algorithm, key_length, 'ENCRYPTION') 
        G().note_sz(str([self.authento._ecu_id, 'SSMA_DENY_MSG_CIPHER_SIZE']), cipher_size)
        
        # monitor
        if encryption_tools.sym_decrypt(message_data.get(), self.authento.sym_key) != None:
            monitor_tag = MonitorTags.CP_ECU_RECEIVE_DENY_MESSAGE
            ecu_id = self.authento._ecu_id
            now = self.sim_env.now
            sender_id = message_data.sender_id
            message_id = can_registration.CAN_STR_AUTH_DENY_MSG
            clear_first = encryption_tools.sym_decrypt(message_data.get(), self.authento.sym_key)[1]
            uid = message_data.unique_id.hex
            G().mon(self.monitor_list, MonitorInput([] , monitor_tag, ecu_id, now, sender_id, message_id, message_data.get(), cipher_size, clear_first, uid))      
        
        return cipher_size
    
    
    def _encryption_size_message_simple_transmit(self, stream_id, message, encryption_time, session_key, uid, passed_encryption_time=False, skip_timeout=False):
        ''' this message returns the size of the encrypted simple message to be
            transmited as well as the encrypted message itself
            
            Input:  stream_id             integer            id of the message to be sent
                    message               object             message that is to be sent
                    encryption_time       float              time it takes to encrypt the message
                    session_key           SymmetricKey       session key for the stream with is stream_id    
                    uid                   uuid               unique id corresponding to this message
            Output: encrypted_message     EncryptedMessage   encrypted message (encrypted using session key for this stream) 
                    encrypted_size        float              size of the encrypted message
        '''
        
        # calculate size
        encrypted_size = EncryptionSize().output_size(len(message), session_key.valid_alg, session_key.valid_key_len, 'ENCRYPTION')  
        
        # encrypt message      
        encrypted_message = SegData(encryption_tools.sym_encrypt(message, session_key), encrypted_size)  
        encrypted_message.unique_id = uid
        encrypted_message.sender_id = self.authento._ecu_id
        # monitor   
        monitor_tag = MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE
        if passed_encryption_time: now = self.sim_env.now
        else: now = self.sim_env.now + encryption_time
        uid = encrypted_message.unique_id.hex
        ecu_id = self.authento._ecu_id
        if not skip_timeout:
            G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, "Unknown", stream_id, message, encrypted_size, stream_id, uid))
        
        # log sending
        L().log(129, self.sim_env.now + encryption_time, self.authento._ecu_id, stream_id, encrypted_message, encrypted_size)
        G().note_sz(str([self.authento._ecu_id, 'LAST_SIMP_MSG_ENC_SEND_SIZE']), encrypted_size) 
        
        return encrypted_message, encrypted_size
    
    
    def _get_nonce(self):
        ''' this message returns the next valid
            nonce that was not used in the defined time
        
            Input:  -
            Output  nonce    number    number used once
        '''
        self._update_taken_nonces()
        nr_uniqe = False
        while not nr_uniqe:
            nonce = random.random()
            nr_uniqe = nonce not in self.taken_nonces
        self.taken_nonces.append(nonce)
        if len(self.taken_nonces) > 10: self.taken_nonces = []
        return nonce
    
    
    def _grant_message_size(self, message_data, message_id, decryption_time):
        ''' returns the size of the encrypted grant message and logs
            necessary information
            
            Input:  message_id      integer    id of the deny message
                    message_data    SegData    incoming deny message
                    decryption_time float      time to decrypt the deny message (already passed)
            Output: cipher_size     float      size of the grant message encrypted   
        '''
        # information
        algorithm = self.authento.sym_key.valid_alg
        key_length = self.authento.sym_key.valid_key_len
        
        # log
        G().note_sz(str([self.authento._ecu_id, 'SSMA_GRANT_MSG_REC_SIZE']), len(message_data))     
        
        # calculate size
        cipher_size = G().call_or_const(self.SSMA_GRANT_MSG_CIPHER_SIZE, self.SSMA_GRANT_MSG_CT_SIZE, algorithm, key_length, 'ENCRYPTION') 
        
        # monitor
        if encryption_tools.sym_decrypt(message_data.get(), self.authento.sym_key) != None:
            monitor_tag = MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE
            ecu_id = self.authento._ecu_id
            now = self.sim_env.now - decryption_time
            sender_id = message_data.sender_id
            message_id = can_registration.CAN_STR_AUTH_DENY_MSG
            first_clear = encryption_tools.sym_decrypt(message_data.get(), self.authento.sym_key)[1]
            uid = message_data.unique_id.hex
            G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, sender_id, message_id, message_data.get(), cipher_size, first_clear, uid))
            
        # log
        G().note_sz(str([self.authento._ecu_id, 'SSMA_GRANT_MSG_CIPHER_SIZE']), cipher_size)
        L().log(130, self.sim_env.now - decryption_time, self.authento._ecu_id, message_id, message_data.get(), cipher_size)
           
        return cipher_size
           
    
    def _grant_notify_sender(self, stream_id, requesting_sender):
        ''' if this ecu is the sender and it receives
            the grant message it will start to send
            now
        
            Input:    stream_id            integer    id of the stream that can be continued
                      requesting_sender    string     ecu id of the ecu that requested this grant message as sender
            Output:   - 
        '''
        try:
            # if requesting ECU continue sending
            if self.sender[stream_id] and self.authento._ecu_id == requesting_sender:
                self.sync[stream_id].put(True)
                
            # if not requesting ECU wait until received anything from the requesting ecu via this stream
            elif self.sender[stream_id]:                
                yield self.sync_message[stream_id].get()  # wait until received from requesting sender, weil geh 
                self.sync[stream_id].put(True)
                
        except:
            pass
    
    
    def _handle_deny_msg(self, message_id, message_data):
        ''' this method handles an incoming deny message. First it is
            decrypted then the deny message is recognized.
            
            Input:  message_id      integer    id of the deny message
                    message_data    SegData    incoming deny message
            Output: -
        '''
       
        # deny cipher size   
        cipher_size = self._deny_message_size(message_data)
        
        # decrption time
        yield self.sim_env.timeout(self._time_decrypt_deny_message(message_id, message_data, cipher_size))     
        
        # decryption process
        clear_message = encryption_tools.sym_decrypt(message_data.get(), self.authento.sym_key)
        
        # Decryption successful: Message for me
        if clear_message != None:
            
            # Monitor             
            self._monitor_deny_clear_ok(message_id, message_data, clear_message)
            
            # extract
            sender_id, stream_id, rec_nonce = clear_message[0], clear_message[1], clear_message[3]  # @UnusedVariable
            
            # check nonce
            if not self._verify_nonce(rec_nonce): L().log(114, self.sim_env.now, self.authento._ecu_id)
            
            # log
            L().log(115, self.authento._ecu_id, stream_id)
            self.sync[stream_id].put(False)
    
     
    def _handle_grant_msg(self, message_id, message_data, decryption_time):
        ''' handles a grant message. First it decrypts the message. If it
            was able to do so the message was meant for it and it will
            receive the session key. IF it is moreover the sender of this
            stream this method will notify the start of the sending process
            
            Input:  message_id      integer    id of the deny message
                    message_data    SegData    incoming deny message
                    decryption_time float      time to decrypt the deny message (already passed)
            Output: -
        '''         
        
        # grant cipher size   
        self._grant_message_size(message_data, message_id, decryption_time)
        
        # decryption process
        clear_message = encryption_tools.sym_decrypt(message_data.get(), self.authento.sym_key)

        # decryption successful
        if clear_message != None:
            
            # monitor
            self._monitor_grant_clear_ok(message_id, message_data, clear_message, decryption_time)
            
            # nonce check
            sender_id, stream_id, session_key, rec_nonce, timestamp, requesting_sender = clear_message  # @UnusedVariable   
            if not self._valid_timest_nonce(timestamp, rec_nonce, stream_id): return
            
            # store session key
            self.session_keys[stream_id] = session_key
            
            L().log(116, self.authento._ecu_id, stream_id)
            # if sender: notify start sending
            self.sim_env.process(self._grant_notify_sender(stream_id, requesting_sender))
            if False: yield self.sim_env.timeout(0)
    
    
    def _init_values(self):
        ''' Initializes the instance variables
        
            Input:     -
            Output:    -
        '''
        
        # Authorization tools
        self.sync = {}  # simpy.Store(self.sim_env, capacity=1)  # Sync Object for sending and receiveing synchronization: dependant on the message id
        self.sync_message = {}  # simpy.Store(self.sim_env, capacity=1) sync object for multiple streams ensuring that ecu only sends when it got a response to its own request
        self.session_keys = {}  # key = [msg_id, sender_id] value = session_key
        self.sender = {}  # key: stream_id // value: I am the sender of this stream
        
        # Nonce and Timestamp
        self.taken_nonces = []
        self.nonce_validity_time = proj.NONCE_VALIDITY
        self.nonce_valid_till = self.nonce_validity_time
        self.nonce = None
        self.timestamp_validity_time = proj.TIMESTAMP_VALIDITY  # Duration 
       
    
    def _log_simple_decryption_end(self, message_id, message_data, decryption_time, clear_message, uid):
        ''' this method logs the current state to the monitor
            
            Input:  message_id        integer        id of the incoming message
                    message_data      SegData        content of the incoming message
                    decryption_time   float          time the decryption of this message took
                    clear_message     object         message that was decrypted
                    uid               uuid           unique id associated to this message
            Output: -  
        '''
        monitor_tag = MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE
        ecu_id = self.authento._ecu_id
        cur_time = self.sim_env.now + decryption_time
        asc_id = message_data.sender_id
        size = len(message_data)
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, cur_time, asc_id, message_id, clear_message, size, message_id, uid.hex))
        
        
    def _log_simple_decryption_start(self, message_data, message_id):
        ''' this method logs the current state to the monitor
            
            Input:   message_data     SegData        content of the incoming message
                     message_id       integer        id of the incoming message
            Output:  uid              uuid           unique id associated to this message
        '''
        
        # monitor
        uid = message_data.unique_id
        monitor_tag = MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE
        asc_id = message_data.sender_id
        size = len(message_data)
        uid_h = message_data.unique_id.hex
        ecu_id = self.authento._ecu_id
        if encryption_tools.sym_decrypt(message_data.get(), self.session_keys[message_id], self.sim_env.now) != None:
            G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, self.sim_env.now, asc_id, message_id, message_data, size, message_id, uid_h))
            
        # log size
        G().note_sz(str([self.authento._ecu_id, 'LAST_SIMP_MSG_ENC_REC_SIZE']), len(message_data)) 
        
        return uid
       
    
    def _log_stream_request_create(self, encryption_time, sent_message, sending_size, stream_id, message):
        ''' logs the monitor input at the end of the stream request message creation
            
            Input:  encryption_time  float      time it takes to encrypt the stream request
                    sent_message     object     message to be sent clear
                    sending_size     float      size of the message that is to be sent
                    stream_id        integer    message id of the message to be sent
                    message          SegData    wrapped message to be sent
        
        '''        
        monitor_tag = MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE
        ecu_id = self.authento._ecu_id
        cur_time = self.sim_env.now + encryption_time
        asc_id = self.authento.sec_id
        msg_id = can_registration.CAN_STR_AUTH_INIT_MSG_STR
        uid = message.unique_id.hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, cur_time, asc_id, msg_id, sent_message, sending_size, stream_id, uid))
       
    
    def _monitor_deny_clear_ok(self, message_id, message_data, clear_message):
        ''' this message logs the information after the deny message
            was decrypted successfully
        
            Input:  message_id      integer    id of the deny message
                    message_data    SegData    incoming deny message
                    clear_message   list       decrypted deny message
            Output: -            
        '''
        # log
        L().log(133, self.sim_env.now, self.authento._ecu_id, clear_message[1], clear_message, self.SSMA_GRANT_MSG_CT_SIZE) 
        L().log(134, self.sim_env.now, self.authento._ecu_id, clear_message[1])
        
        # monitor
        monitor_tag = MonitorTags.CP_ECU_DECRYPTED_DENY_MESSAGE
        ecu_id = self.authento._ecu_id
        now = self.sim_env.now
        sender_id = message_data.sender_id
        message_id = can_registration.CAN_STR_AUTH_DENY_MSG
        size = self.SSMA_GRANT_MSG_CT_SIZE
        stream_id = clear_message[1]
        uid = message_data.unique_id.hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, sender_id, message_id, message_data, size, stream_id, uid))
       
    
    def _monitor_grant_clear_ok(self, message_id, message_data, clear_message, decryption_time):
        ''' logs successful decryption of the grant message
            
            Input:  message_id      integer    id of the deny message
                    message_data    SegData    incoming deny message
                    clear_message   list       decrypted deny message
            Output: -  
        '''
        # log
        L().log(131, self.sim_env.now , self.authento._ecu_id, message_id, clear_message, self.SSMA_GRANT_MSG_CT_SIZE)
        L().log(135, self.sim_env.now , self.authento._ecu_id, message_id)    
        
        # monitor
        monitor_tag = MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE
        now = self.sim_env.now 
        sender_id = message_data.sender_id
        can_registration.CAN_STR_AUTH_GRANT_MSG
        size = self.SSMA_GRANT_MSG_CT_SIZE
        message = clear_message[1]
        uid = message_data.unique_id.hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self.authento._ecu_id, now, sender_id, message_id, message_data, size, message, uid))
       
    
    def _reset_init_msg_stream(self, msg_id):
        try:
            for a in self.sync.keys():
                self.sync[a].items = []
        except:
            pass
        self.sender[msg_id] = True
        
    
    def _session_key_simple_encryption(self, stream_id, message, encryption_time, passed_encryption_time=False, skip_timeout=False):
        ''' this method returns the session key 
            corresponding to the given stream_id
            during the simple message encryption 
            process
            
            Input:  stream_id    integer        stream corresponding to requested session key
                    message      object         message to be encrypted
            Output: session_key  SymmetricKey   session key for the stream with is stream_id          
                    uid          uuid           unique id corresponding to this message
        '''
        # monitor
        uid = uuid.uuid4()
        monitor_tag = MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE
        ecu_id = self.authento._ecu_id
        size = len(message)        
        if passed_encryption_time: now = self.sim_env.now - encryption_time
        else: now = self.sim_env.now        
        if not skip_timeout:
            G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, "Unknown", stream_id, message, size, stream_id, uid.hex))
        
        # get session key
        session_key = self.session_keys[stream_id]
        
        # log
        L().log(128, self.sim_env.now, self.authento._ecu_id, stream_id, message, len(message))
        G().note_sz(str([self.authento._ecu_id, 'LAST_SIMP_MSG_UNENC_SEND_SIZE']), len(message))    
    
        return session_key, uid
        
    
    def _stream_request_cipher_size(self, encryption_time, encrypted_message):
        ''' this method returns the size of the stream 
            request message
            
            Input: encryption_time       float              time it takes to encrypt the stream request
                   encrypted_message     EncryptedMessage   encrypted message (encrypted using session key for this stream)
        '''
        
        sending_size = G().call_or_const(self.SCCM_ECU_REQ_MSG_SIZE, self.SSMA_SIZE_REQ_MSG_CONTENT, self.SCCM_ECU_SYM_KEY_ENC_ALG, self.SCCM_ECU_SYM_KEY_ENC_KEY_LEN, 'ENCRYPTION')   
        
        G().note_sz(str([self.authento._ecu_id, 'SCCM_ECU_REQ_MSG_SIZE']), sending_size)
        L().log(127, self.sim_env.now + encryption_time, self.authento._ecu_id, encrypted_message, sending_size)
                
        return sending_size
        
    
    def _stream_request_time_message(self, stream_id):
        ''' this method will return the time it takes to encrypt
            the stream request message as well as the stream request
            message itself
        
            Input:   stream_id        integer    message stream this ecu tries to get granted by the security module
            Output:  encryption_time  float      time to encrypt the stream request message
                     request_message  SegData    stream request message for the requested stream with id stream_id            
        '''
        
        # calculate time
        encryption_time = time.call(self.SCCM_STREAM_ENC_REQ_MSG, self.SSMA_SIZE_REQ_MSG_CONTENT, self.SCCM_ECU_SYM_KEY_ENC_ALG, self.SCCM_ECU_SYM_KEY_ENC_KEY_LEN, self.SCCM_ECU_SYM_KEY_ENC_ALG_MODE)
        encryption_time *= self._jitter
        
        # create request 
        request_message = self._create_stream_request_message(stream_id, encryption_time)
        
        # log
        G().to_t(self.sim_env, encryption_time , 'SCCM_STREAM_ENC_REQ_MSG', self.__class__.__name__, self.authento._ecu_id)
        
        return encryption_time, request_message
        
    
    def _time_decrypt_deny_message(self, message_id, message_data, cipher_size):
        ''' returns the time it takes to decrypt the deny 
            message
            
            Input:  message_id      integer    id of the deny message
                    message_data    SegData    incoming deny message
                    cipher_size     float      size of the deny message encrypted
            Output: decryption_time float      time to decrypt the deny message   
            
        '''
        # calculate time
        decryption_time = time.call(self.SCCM_STREAM_DEC_DENY_MSG, self.authento.sym_key.valid_alg, self.authento.sym_key.valid_key_len, cipher_size, self.authento.sym_key.valid_alg_mode) 
        decryption_time *= self._jitter
        
        # log
        L().log(132, self.sim_env.now, self.authento._ecu_id, message_id, message_data.get(), cipher_size)        
        G().to_t(self.sim_env, decryption_time , 'SCCM_STREAM_DEC_DENY_MSG', self.__class__.__name__, self.authento._ecu_id)
    
        return decryption_time
        
    
    def _time_decrypt_grant_message(self):
        ''' this message returns the time it takes to decrypt
            the grant message that was send by the 
            security module and receied here
            
            Input:     -
            Output:    decryption_time    float    time to decrypt the grant message
        '''
        
        # extract
        algorithm = self.authento.sym_key.valid_alg
        algorithm_mode = self.authento.sym_key.valid_alg_mode
        key_length = self.authento.sym_key.valid_key_len
        
        # timeout
        cipher_size = G().call_or_const(self.SSMA_GRANT_MSG_CIPHER_SIZE, self.SSMA_GRANT_MSG_CT_SIZE, algorithm, key_length, 'ENCRYPTION') 
        time_val = time.call(self.SCCM_STREAM_DEC_GRANT_MSG, algorithm, key_length, cipher_size, algorithm_mode) * self._jitter   
        
        # log value
        G().to_t(self.sim_env, time_val , 'SCCM_STREAM_DEC_GRANT_MSG', self.__class__.__name__, self.authento._ecu_id)

        return time_val
        
    
    def _update_taken_nonces(self):        
        while self.sim_env.now >= self.nonce_valid_till:
            self.taken_nonces = []
            self.nonce_valid_till += self.nonce_validity_time
    
    
    def _valid_timest_nonce(self, timestamp, rec_nonce, stream_id):
        ''' True if both the timestamp and the received nonce
            are valid. Else False. Fills sync object with false
            so that the sending process will be aborted'''
        
        # check timestamp
        if timestamp - self.timestamp_validity_time >= self.sim_env.now:
            self.sync[stream_id].put(False)
            return G().val_log_info(False, 117, self.sim_env.now, self.authento._ecu_id, timestamp)
        
        # check nonce
        if not self._verify_nonce(rec_nonce):
            self.sync[stream_id].put(False)
            return G().val_log_info(False, 118, self.sim_env.now, self.authento._ecu_id)
        
        return True
    
    
    def _verify_nonce(self, rec_nonce):
        return True
    
class StdAuthentor(object):
    '''
    This class implements the ECU Side of a ECU Authentication 
    based on the proposed scheme
    '''
        
    def __init__(self, sim_env, transport_layer, MessageClass, ecu_id, symmetric_enc_algorithm, symmetric_enc_key_length, assymmetric_enc_algorithm, \
                 assymmetric_enc_alg_option, assymmetric_enc_key_length, symmetric_enc_algorithm_mode=False, monitor_list=[], jitter=1):
        ''' Constructor
            
            Input:  sim_env                        simpy.Environment        environment of this component
                    transport_layer                AbstractTransportLayer   transport layer connected to the communication module
                    MessageClass                   AbstractBusMessage       class of the messages  how they are sent on the CAN Bus
                    ecu_id                         string                   id of the corresponding AbstractECU
                    symmetric_enc_algorithm        SymAuthMechEnum          symmetric algorithm used for the ECU communication with the security module (not session key)
                    symmetric_enc_key_length       AuKeyLengthEnum          symmetric algorithm key length used for the ECU communication with the security module (not session key)
                    symmetric_enc_algorithm_mode   SymAuthMechEnum          symmetric algorithm mode used for the ECU communication with the security module (not session key)
                    assymmetric_enc_algorithm      AsymAuthMechEnum         asymmetric algorithm used to exchange initial information between ECU and security module
                    assymmetric_enc_alg_option     number/string/...        asymmetric algorithm option used to exchange initial information between ECU and security module
                    assymmetric_enc_key_length     AuKeyLengthEnum          asymmetric algorithm key length used to exchange initial information between ECU and security module
                    monitor_list                   RefList                  list of monitor inputs   
                    jitter                         float                    random value multiplied on each timeout
            Output:  -
        '''
        
        # set passed values
        self.transp_lay = transport_layer
        self.MessageClass = MessageClass
        self.sim_env = sim_env        
        self.monitor_list = monitor_list      
        self._ecu_id = ecu_id  
        self._jitter = jitter
        self._received_sec_mod_advert = False
        
        # initialize values of security mechanism
        self.SCCM_ECU_SYM_KEY_ENC_ALG = symmetric_enc_algorithm
        self.SCCM_ECU_SYM_KEY_ENC_ALG_MODE = symmetric_enc_algorithm_mode
        self.SCCM_ECU_SYM_KEY_ENC_KEY_LEN = symmetric_enc_key_length
        self.SCCM_ECU_PUB_ENC_ALG = assymmetric_enc_algorithm
        self.SCCM_ECU_PUB_ENC_ALG_OPTION = assymmetric_enc_alg_option
        self.SCCM_ECU_PUB_ENC_KEY_LEN = assymmetric_enc_key_length        
        self._init_sec_vals(symmetric_enc_algorithm, symmetric_enc_key_length, symmetric_enc_algorithm_mode, assymmetric_enc_algorithm, assymmetric_enc_key_length)

        # timing parameter
        self.SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY = time.SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY
        self.SCCM_ECU_ENC_REG_MSG_INNER = time.SCCM_ECU_ENC_REG_MSG_INNER
        self.SCCM_ECU_HASH_REG_MSG = time.SCCM_ECU_HASH_REG_MSG
        self.SCCM_ECU_ENC_REG_MSG_OUTTER = time.SCCM_ECU_ENC_REG_MSG_OUTTER
        self.SCCM_ECU_ADV_SEC_MOD_CERT_VAL = time.SCCM_ECU_ADV_SEC_MOD_CERT_VAL
        self.SCCM_ECU_DEC_CONF_MSG = time.SCCM_ECU_DEC_CONF_MSG

        # project parameter
        self.SCCM_ECU_REG_MSG_HASH = proj.SCCM_ECU_REG_MSG_HASH
        self.SCCM_ECU_REG_MSG_SIZE = proj.SCCM_ECU_REG_MSG_SIZE
        self.SSMA_REG_MSG_CT_SIZE_INNER = proj.SSMA_REG_MSG_CT_SIZE_INNER
        self.SCCM_ECU_REG_MSG_HASH_LEN = proj.SCCM_ECU_REG_MSG_HASH_LEN
        self.SSMA_SECM_PUB_ENC_ALG = proj.SSMA_SECM_PUB_ENC_ALG
        self.SSMA_SECM_PUB_ENC_ALG_OPTION = proj.SSMA_SECM_PUB_ENC_ALG_OPTION
        self.SSMA_REG_MSG_CIPHER_SIZE_INNER = proj.SSMA_REG_MSG_CIPHER_SIZE_INNER        
        self.SSMA_REG_MSG_CIPHER_SIZE_OUTER = proj.SSMA_REG_MSG_CIPHER_SIZE_OUTER
        self.SSMA_SECM_PUB_ENC_KEY_LEN = proj.SSMA_SECM_PUB_ENC_KEY_LEN
        
        self.ECU_CERT_HASHING_MECH = proj.ECU_CERT_HASHING_MECH
        self.ECU_CERT_ENCRYPTION_MECH = proj.ECU_CERT_ENCRYPTION_MECH
        self.ECU_CERT_ENCRYPTION_MECH_OPTION = proj.ECU_CERT_ENCRYPTION_MECH_OPTION
        self.ECU_CERT_KEYL = proj.ECU_CERT_KEYL
        self.ECU_CERT_CA_LEN = proj.ECU_CERT_CA_LEN
        self.ECU_CERT_SIZE_HASH_TO_SIGN = proj.ECU_CERT_SIZE_HASH_TO_SIGN
        self.ECU_CERT_SIZE_HASH = proj.ECU_CERT_SIZE_HASH
        self.ECU_CERT_SIZE = proj.ECU_CERT_SIZE
        self.SCCM_ECU_CONF_MSG_SIZE = proj.SCCM_ECU_CONF_MSG_SIZE
        
        # parameter of security module certificate
        self.SECMOD_CERT_HASHING_MECH = proj.SECMOD_CERT_HASHING_MECH
        self.SECMOD_CERT_ENCRYPTION_MECH = proj.SECMOD_CERT_ENCRYPTION_MECH    
        self.SECMOD_CERT_ENCRYPTION_MECH_OPTION = proj.SECMOD_CERT_ENCRYPTION_MECH_OPTION        
        self.SECMOD_CERT_KEYL = proj.SECMOD_CERT_KEYL
        self.SECMOD_CERT_CA_LEN = proj.SECMOD_CERT_CA_LEN                  
        self.SECMOD_CERT_SIZE_HASH_TO_SIGN = proj.SECMOD_CERT_SIZE_HASH_TO_SIGN
        self.SECMOD_CERT_SIZE_HASH_SIGNED = proj.SECMOD_CERT_SIZE_HASH_SIGNED
        self.SCCM_ECU_CONF_MSG_CIPHER_SIZE = proj.SCCM_ECU_CONF_MSG_CIPHER_SIZE

    
    def activate(self):
        ''' activates the ECU authentication
            
            Input:      -
            Output:     -
        '''
        self.active = True        
    
    
    def process(self, message_id, message_data):
        ''' processes ECU Authentication messages that were received
            
            Input:      message_id         integer        message id of the received message
                        message_data       SegData        message that was received
            Output:     -
        '''
        
        # ECU already authenticated
        if self.confirmed and can_registration.CAN_ECU_AUTH_ADVERTISE == message_id:
            return self._warn_already_authenticated(message_data)
            
        # received ECU advertisement: allowed once
        if can_registration.CAN_ECU_AUTH_ADVERTISE == message_id and not self._received_sec_mod_advert:     
            yield self.sim_env.process(self._handle_ecu_advertisement_message(message_data))
            
        # received confirmation message
        if can_registration.CAN_ECU_AUTH_CONF_MSG == message_id:
            yield self.sim_env.process(self._handle_ecu_confirmation_message(message_data))
           
     
    def _create_reg_msg(self):
        ''' creates a registration message for the 
            connected security module
            
            Input:    -
            Output:   message        SegData        registration message that is sent to the security module
        '''
        
        # nonce & timestamp    
        nonce, timestamp, uid = self._start_create_registration_message()
                
        # create symmetric ECU key           
        yield self.sim_env.timeout(self._key_generation_time_registration_message())
        
        # log
        self._log_creation_encrypt_inner_registration_message(nonce, timestamp, uid)
        
        # inner encryption time
        yield self.sim_env.timeout(self._inner_encryption_time_registration_message())     
        
        # inner encryption process
        registration_message_1 = self._inner_encryption_registration_message(nonce, timestamp, uid)

        # outer hashing
        hashed_outer_message, hashing_time = self._hash_outer_message_time(nonce, timestamp)        
        yield self.sim_env.timeout(hashing_time)   
          
        # outer encryption time  
        encryption_time, hashed_size = self._outer_encryption_time_registration_message(hashed_outer_message, uid)
        yield self.sim_env.timeout(encryption_time)    
                        
        # outer encryption process
        registration_message_2 = self._outer_encryption_registration_message(hashed_outer_message, uid)

        # concatenate
        registration_message = [registration_message_1, registration_message_2, self.ecu_certificate]
        self.ecu_certificate.size = self.ECU_CERT_SIZE 
        
        # sending Size 
        registration_message_size = self._registration_message_size(hashed_size, registration_message)
                
        # create message
        message = SegData(registration_message, registration_message_size, unique_id=uid)

        # monitor
        self._log_registration_message_end(registration_message, registration_message_size, message)
        
        # log 
        L().log(121, self._ecu_id, message.get())       
        
        return message
           
    
    def _get_nonce(self):
        ''' this message generates a nonce that was 
            not used in a given interval
            
            Input:    -
            Output:   nonce    number    number  used once
        '''
        # update existing nonces
        self._update_taken_nonces()
        nr_uniqe = False
        
        # determine new
        while not nr_uniqe:
            nonce = random.random()
            nr_uniqe = nonce not in self.taken_nonces
        
        # add to used
        self.taken_nonces.append(nonce)
        if len(self.taken_nonces) > 10: self.taken_nonces = []
        return nonce
                         
    @ try_ex
    def _check_advertisement_certificate(self, certificate, certificate_size, uid):
        ''' this method checks if the ecu advertisement certificate is valid. If it is
            not valid False will be returned. If another error occurred None will be
            returned
            
            Input:  certificate         ECUCertificate    the certificate of the security module
                    certificate_size    float             the size of the security module's certificate
                    uid                 uuid              unique id corresponding to this message
            Output: bool                boolean           None at error, False if certificate invalid, True if certificate valid
        '''
        
        # check certificate
        try:
            certificate_valid = encryption_tools.certificate_trustworthy(certificate, self.lst_root_cert, self.sim_env.now)
        except:
            L().log_err_traceback(3)
            return None      
        
        # log
        L().log(120, self._ecu_id, certificate_valid)
        if not certificate_valid: 
            L().log_err(2)
            return None
        
        # Monitor              
        monitor_tag = MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE
        ecu_id = self._ecu_id
        now = self.sim_env.now
        asc_id = certificate.user_id
        message_id = can_registration.CAN_ECU_AUTH_ADVERTISE
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, asc_id, message_id, certificate, certificate_size, -1, uid.hex))
           
        return certificate_valid
    
     
    def _confirmation_nonce_valid(self, clear_message):
        ''' this method returns true if the nonce given in the 
            confirmation message is valid
            
            Input:    clear_message    list           decrypted confirmation message
            Output:   bool             boolean        true if the nonce is valid 
        ''' 
        # log
        L().log(145, self.sim_env.now, self._ecu_id, clear_message, self.SCCM_ECU_CONF_MSG_SIZE) 
        
        # check nonce
        received_nonce, timestamp = clear_message[1], clear_message[2]            
        if not self._valid_timest_nonce(timestamp, received_nonce):
            return False
        
        return True  
       
               
    def _ecu_certificate_verification_time(self, certificate_size, certificate):
        ''' this method returns the time it takes to verify the certificate of
            the security module when it was received in the ecu advertisement
            message
            
            Input:    certificate_size    float            size of the received certificate
                      certificate         ECUCertificate   certificate of the security module
            Output:   verification_time   float            time needed to verify the security module certificate
        '''
        
        # size of the hash
        hash_size = G().call_or_const(self.SECMOD_CERT_SIZE_HASH_TO_SIGN, certificate_size, self.SECMOD_CERT_HASHING_MECH, None, 'HASH')
        G().note_sz(str([self._ecu_id, 'SECMOD_CERT_SIZE_HASH_TO_SIGN']), hash_size)
        
        # size of the signature
        signed_size = G().call_or_const(self.SECMOD_CERT_SIZE_HASH_SIGNED, hash_size, self.SECMOD_CERT_ENCRYPTION_MECH, self.SECMOD_CERT_KEYL, 'SIGN')
        G().note_sz(str([self._ecu_id, 'SECMOD_CERT_SIZE_HASH_SIGNED']), signed_size)
        
        # time to verify the signature
        verification_time = time.call(self.SCCM_ECU_ADV_SEC_MOD_CERT_VAL, self.SECMOD_CERT_HASHING_MECH, self.SECMOD_CERT_ENCRYPTION_MECH, \
                                    self.SECMOD_CERT_KEYL, self.SECMOD_CERT_CA_LEN, hash_size, signed_size, self.SECMOD_CERT_ENCRYPTION_MECH_OPTION, certificate_size)
        verification_time *= self._jitter
                                    
        # log
        L().log(136, self.sim_env.now, self._ecu_id, certificate, signed_size)
        G().to_t(self.sim_env, verification_time , 'SCCM_ECU_ADV_SEC_MOD_CERT_VAL', self.__class__.__name__, self._ecu_id) 
             
        return verification_time
       
        
    def _extract_advertisement_initial(self, message_data):
        ''' this method extracts the relevant parameters from the
            advertisement message and returns them
        
            Input:     message_data      SegData            received ECU advertisement message
            Output:    extracted_data    ECUCertificate     the extracted ecu certificate
                       certificate_size  float              size of the received certificate
                       uid               uuid               unique identifier of this message
        '''
        
        # received size
        certificate_size = len(message_data)
        
        # monitor
        uid = message_data.unique_id
        monitor_tag = MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT
        now = self.sim_env.now
        message_id = can_registration.CAN_ECU_AUTH_ADVERTISE
        u_id = message_data.unique_id.hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self._ecu_id, now, self.sec_id, message_id, message_data.get(), certificate_size, -1, u_id))  # LOG 
        
        # log
        L().log(119, self.sim_env.now, self._ecu_id); G().note_sz(str([self._ecu_id, 'ECU_ADV_SENDING_SIZE']), len(message_data))
        
        # extract
        extracted_data = message_data.get()
        
        return extracted_data, certificate_size, uid
       
          
    def _extract_confirmation_message_time(self, message_data):
        ''' this method reads in the information received from the
            confirmation message and returns the time it takes to
            decrypt the message as well as the message in encrypted
            state
            
            Input:     message_data    SegData             message received: Confirmation message from security module
            Output:    message         EncryptedMessage    confirmation message encrypted
                       decyption_time  float               time it takes to decrypt the confirmation message
        '''
          
        # extract  
        extracted_message = message_data.get()
        G().note_sz(str([self._ecu_id, 'ECU_CONF_MSG_SENDING_SIZE']), len(message_data))
        
        # cipher size
        cipher_size = G().call_or_const(self.SCCM_ECU_CONF_MSG_CIPHER_SIZE, self.SCCM_ECU_CONF_MSG_SIZE, self.SCCM_ECU_SYM_KEY_ENC_ALG, self.SCCM_ECU_SYM_KEY_ENC_KEY_LEN, 'ENCRYPTION')
        
        # if decryptable monitor
        if encryption_tools.sym_decrypt(message_data.get(), self.sym_key) != None:
            monitor_tag = MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE
            ecu_id = self._ecu_id
            now = self.sim_env.now
            message_id = can_registration.CAN_ECU_AUTH_CONF_MSG
            u_id = message_data.unique_id.hex
            G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, self.sec_id, message_id, extracted_message, cipher_size, -1, u_id)) 

        # log
        L().log(144, self.sim_env.now, self._ecu_id, extracted_message, cipher_size); G().note_sz(str([self._ecu_id, 'SCCM_ECU_CONF_MSG_CIPHER_SIZE']), cipher_size) 
        
        # calculate time
        decryption_time = time.call(self.SCCM_ECU_DEC_CONF_MSG, self.SCCM_ECU_SYM_KEY_ENC_ALG, self.SCCM_ECU_SYM_KEY_ENC_KEY_LEN, cipher_size, self.SCCM_ECU_SYM_KEY_ENC_ALG_MODE) 
        decryption_time *= self._jitter
        
        # log time
        G().to_t(self.sim_env, decryption_time, 'SCCM_ECU_DEC_CONF_MSG', self.__class__.__name__, self._ecu_id)

        return extracted_message, decryption_time
    
    
    def _handle_ecu_advertisement_message(self, message_data):
        ''' handles the the ecu advertisement message. When the message is 
            received the certificate of the security module is validated and 
            if it is valid a registration message will be sent to the security
            module
        
            Input:    message_data    SegData    received ecu advertisement message
        '''
        
        # Receive Message
        certificate, certificate_size, uid = self._extract_advertisement_initial(message_data)
                   
        # verify certificate time
        yield self.sim_env.timeout(self._ecu_certificate_verification_time(certificate_size, certificate))    
                
        # verify certificate process
        certificate_valid = self._check_advertisement_certificate(certificate, certificate_size, uid)
        if certificate_valid == None: return
        
        # Send Registration Message
        if certificate_valid:
            registration_message = yield self.sim_env.process(self._create_reg_msg())
            yield self.sim_env.process(self.transp_lay.send_msg(self._ecu_id, can_registration.CAN_ECU_AUTH_REG_MSG, registration_message)) 
        
        # set already received to true
        self._received_sec_mod_advert = True
      
    
    def _handle_ecu_confirmation_message(self, message_data):
        ''' handles the actions after to a ECU Confirmation Message 
        
            Input:     message_data    SegData             message received: Confirmation message from security module
            Output:    -        
        '''
                
        # decryption time
        message, decryption_time = self._extract_confirmation_message_time(message_data)        
        yield self.sim_env.timeout(decryption_time)
        
        # decryption process
        clear_message = encryption_tools.sym_decrypt(message, self.sym_key)
        
        # message verified
        if(clear_message != None):
            
            # nonce valid
            if not self._confirmation_nonce_valid(clear_message): return
           
            # received confirmation
            if(self._ecu_id == clear_message[0]):                    
                L().log(122, self.sim_env.now, self._ecu_id)
                self.confirmed = True
            
            # monitor
            self._monitor_confirmation_end(message_data)

            
    def _hash_outer_message_time(self, nonce, timestamp):
        ''' this method hashes the outer registration message and returns
            the message in a hashed version. Above that it determines the
            time needed for this hashing process
            
            Input:  nonce                    number            number used once
                    timestamp                float             current time
            Output: hashed_outer_message     HashedMessage     hashed version of the inner registration part [self.sec_id, self.sym_key, nonce, timestamp]
                    hashing_time             float             time it takes to hash the inner part of the message   
        '''
        L().log(140, self.sim_env.now , self._ecu_id, [self.sec_id, self.sym_key, nonce, timestamp], self.SSMA_REG_MSG_CT_SIZE_INNER)
        hashing_time = time.call(self.SCCM_ECU_HASH_REG_MSG, self.SSMA_REG_MSG_CT_SIZE_INNER, self.SCCM_ECU_REG_MSG_HASH) * self._jitter
        
        G().to_t(self.sim_env, hashing_time , 'SCCM_ECU_HASH_REG_MSG', self.__class__.__name__, self._ecu_id)
        hashed_outer_message = HashedMessage([self.sec_id, self.sym_key, nonce, timestamp], self.SCCM_ECU_REG_MSG_HASH) 
        
        
        return hashed_outer_message, hashing_time
        
    
    def _init_sec_vals(self, sym_enc_alg, sym_enc_key_len, sym_enc_alg_mode, assym_enc_alg, assym_enc_key_len):
        ''' initializes variables for the security communication'''
        
        # Control variables 
        self.active = False  # Authentication active    
        self.confirmed = False  # Confirmation received        
              
        # Certification
        self.lst_root_cert = []  # List of root certificates                 
        
        # create and add keys
        self.sym_key = encryption_tools.sym_get_key(sym_enc_alg, sym_enc_key_len, sym_enc_alg_mode)     
        self.priv_key, self.pub_key = encryption_tools.asy_get_key_pair(assym_enc_alg, assym_enc_key_len)
        
        self.key_manage = PublicKeyManager()
        self.key_manage.add_key(self._ecu_id, self.pub_key) 
        
        # Nonce and timestamp
        self.taken_nonces = []
        self.nonce_validity_time = proj.NONCE_VALIDITY
        self.nonce_valid_till = self.nonce_validity_time
        self.timestamp_validity = proj.TIMESTAMP_VALIDITY
    
        
    def _inner_encryption_registration_message(self, nonce, timestamp, uid):
        ''' this message encrypts the first part of the registration message
            and returns it
        
            Input:  nonce                number            number used once
                    timestamp            float             current time
                    uid                  uuid              unique id associated with this message
            Output: encrypted_message    EncryptedMessage  first part of the registration message
        '''
        # monitor
        monitor_tag = MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE
        ecu_id = self._ecu_id
        now = self.sim_env.now
        message_id = can_registration.CAN_ECU_AUTH_REG_MSG
        message = "Encrypted Message"
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, self.sec_id, message_id, message, -1, -1, uid.hex))
        
        # encrypt message
        encrypted_message = encryption_tools.asy_encrypt([self.sec_id, self.sym_key, nonce, timestamp], self.key_manage.pub_key[self.sec_id])
        
        return encrypted_message
    
    
    def _inner_encryption_time_registration_message(self):
        ''' this method determines the encryption time needed for the encryption
            of the inner part of the registration message
            
            Input:     -
            Output:    encryption_time    float    time needed for encryption
        '''
        # calculate time
        encryption_time = time.call(self.SCCM_ECU_ENC_REG_MSG_INNER, self.SSMA_REG_MSG_CT_SIZE_INNER, self.SSMA_SECM_PUB_ENC_ALG, \
                                    self.SSMA_SECM_PUB_ENC_KEY_LEN, self.SSMA_SECM_PUB_ENC_ALG_OPTION) * self._jitter
        
        # log
        G().to_t(self.sim_env, encryption_time , 'SCCM_ECU_ENC_REG_MSG_INNER', self.__class__.__name__, self._ecu_id)
        
        return encryption_time
     
       
    def _key_generation_time_registration_message(self):
        ''' this method returns the time needed to generate the symmetric ecu key sent
            in the registration message
            
            Input:     -
            Output:    creation_time     float    time to generate the symmetric ecu key
            
            '''
        creation_time = time.call(self.SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY, self.SCCM_ECU_SYM_KEY_ENC_ALG, self.SCCM_ECU_SYM_KEY_ENC_KEY_LEN) * self._jitter
        G().to_t(self.sim_env, creation_time , 'SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY', self.__class__.__name__, self._ecu_id)       
        return creation_time
        
    
    def _log_creation_encrypt_inner_registration_message(self, nonce, timestamp, uid):
        ''' this method logs the processing step between the creation 
            of the registration message and the begin of the inner
            message decryption
        
            Input:  nonce        number        number used once
                    timestamp    float         current time
                    uid          uuid          unique id associated with this message
            Output: -
        '''
        
        # monitor
        monitor_tag = MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE
        ecu_id = self._ecu_id
        now = self.sim_env.now
        message_id = can_registration.CAN_ECU_AUTH_REG_MSG
        message = [self.sec_id, self.sym_key, nonce, timestamp]
        size = self.SSMA_REG_MSG_CT_SIZE_INNER
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, self.sec_id, message_id, message, size, -1, uid.hex))  # LOG 
        
        # log
        L().log(139, self.sim_env.now , self._ecu_id, [self.sec_id, self.sym_key, nonce, timestamp], self.SSMA_REG_MSG_CT_SIZE_INNER)
        
        # log size
        G().note_sz(str([self._ecu_id, 'SSMA_REG_MSG_CT_SIZE_INNER']), self.SSMA_REG_MSG_CT_SIZE_INNER)
        
       
    def _monitor_confirmation_end(self, message_data):
        ''' this message monitors and logs the end of the confirmation message
            reception process
            
            Input:     message_data    SegData             message received: Confirmation message from security module
            Output:    -
        '''
        # monitor
        monitor_tag = MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE
        now = self.sim_env.now
        sender_id = self.sec_id
        message_id = can_registration.CAN_ECU_AUTH_CONF_MSG
        size = self.SCCM_ECU_CONF_MSG_SIZE
        u_id = message_data.unique_id.hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self._ecu_id, now, sender_id, message_id, message_data, size, -1, u_id))
        
    
    def _outer_encryption_time_registration_message(self, hashed_outer_message, uid):
        ''' this method returns the time needed to encrypt the outer part
            of the registration message given the hashed inner part of the
            registration message
            
            Input:    hashed_outer_message    HashedMessage     hashed version of the inner registration part [self.sec_id, self.sym_key, nonce, timestamp]
                      uid                     uuid              unique id associated with this message
            Output:   encryption_time         float             time needed to encrypt the given hashed message
                      hashed_size             float             size of the hashed message
        '''
        
        # determine hash size 
        hashed_size = G().call_or_const(self.SCCM_ECU_REG_MSG_HASH_LEN, self.SSMA_REG_MSG_CT_SIZE_INNER, self.SCCM_ECU_REG_MSG_HASH, None, 'HASH')
        
        # monitor
        monitor_tag = MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE
        now = self.sim_env.now
        message_id = can_registration.CAN_ECU_AUTH_REG_MSG
        message = "HashedMessage"
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self._ecu_id, now, self.sec_id, message_id, message, hashed_size, -1, uid.hex))  # LOG 
        
        # log size
        L().log(141, self.sim_env.now , self._ecu_id, hashed_outer_message, hashed_size)
        G().note_sz(str([self._ecu_id, 'SCCM_ECU_REG_MSG_HASH_LEN']), hashed_size)
        
        # calculate time
        encryption_time = time.call(self.SCCM_ECU_ENC_REG_MSG_OUTTER, hashed_size, self.SCCM_ECU_PUB_ENC_ALG, self.SCCM_ECU_PUB_ENC_KEY_LEN, self.SCCM_ECU_PUB_ENC_ALG_OPTION)
        encryption_time *= self._jitter
        
        # log time
        G().to_t(self.sim_env, encryption_time , 'SCCM_ECU_ENC_REG_MSG_OUTTER', self.__class__.__name__, self._ecu_id)
        
        return encryption_time, hashed_size
        
    
    def _log_registration_message_end(self, registration_message, registration_message_size, message):
        ''' this method logs the end of the registration message's
            creation process
            
            Input:    registration_message             list        registration message as a whole
                      registration_message_size        float       size of the registration message to be sent
                      message                          SegData     resulting message that will be actualy sent
            Output:   -
        '''
        # monitor
        monitor_tag = MonitorTags.CP_ECU_SEND_REG_MESSAGE
        ecu_id = self._ecu_id
        now = self.sim_env.now
        message_id = can_registration.CAN_ECU_AUTH_REG_MSG
        uid = message.unique_id.hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, self.sec_id, message_id, registration_message, registration_message_size, -1, uid))

    
    def _outer_encryption_registration_message(self, hashed_outer_message, uid):
        ''' this method hashes the outer hash that is passed and returns
            the encrypted version of it, which is the second part of the
            registration message
            
            Input:    hashed_outer_message        HashedMessage        hashed inner part of the registration message
                      uid                         uuid                 unique id associated with this message
            Output:   registration_second_part    EncryptedMessage     encrypted hash 
            
        '''
        # monitor
        monitor_tag = MonitorTags.CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE
        now = self.sim_env.now
        message_id = can_registration.CAN_ECU_AUTH_REG_MSG
        message = "EncryptedMessage"
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self._ecu_id, now, self.sec_id, message_id, message, -1, -1, uid.hex)) 
        
        # encrypt
        registration_second_part = encryption_tools.asy_encrypt(hashed_outer_message, self.priv_key)
        
        return registration_second_part
        
    
    def _registration_message_size(self, hashed_size, registration_message):
        ''' this method returns the size of the registration message as it is 
            sent
            
            Input:    hashed_size            float        size of the hashed registration message
                      registration_message   list         registration message as it is sent
            Output:   total_size             float        overall size of the whole registration message
        '''
        
        if not isinstance(self.SCCM_ECU_REG_MSG_SIZE, (int, float, complex)):
            
            # registration message 1
            rm1_size = G().call_or_const(self.SSMA_REG_MSG_CIPHER_SIZE_INNER, self.SSMA_REG_MSG_CT_SIZE_INNER, self.SSMA_SECM_PUB_ENC_ALG, self.SSMA_SECM_PUB_ENC_KEY_LEN, 'ENCRYPTION')
            G().note_sz(str([self._ecu_id, 'SSMA_REG_MSG_CIPHER_SIZE_INNER']), rm1_size)
            
            # registration message 2            
            rm2_size = G().call_or_const(self.SSMA_REG_MSG_CIPHER_SIZE_OUTER, hashed_size, self.SCCM_ECU_PUB_ENC_ALG, self.SCCM_ECU_PUB_ENC_KEY_LEN, 'SIGN')
            G().note_sz(str([self._ecu_id, 'SSMA_REG_MSG_CIPHER_SIZE_OUTER']), rm2_size)
            
            # registration message 3
            cert_size = self.ECU_CERT_SIZE; G().note_sz(str([self._ecu_id, 'ECU_CERT_SIZE']), cert_size)
            total_size = rm1_size + rm2_size + cert_size
            
            # log
            L().log(142, self.sim_env.now , self._ecu_id, registration_message, rm1_size, rm2_size, cert_size, total_size)
            
        else:
            # fixed size used
            total_size = self.SCCM_ECU_REG_MSG_SIZE
            L().log(143, self.sim_env.now , self._ecu_id, registration_message, total_size)   
            
        # note size used   
        G().note_sz(str([self._ecu_id, 'SCCM_ECU_REG_MSG_SIZE']), total_size)
        
        return total_size
        
    
    def _start_create_registration_message(self):
        ''' this method logs the initial information of the registration message
            creation and returns the created nonce and timestamp for the process
            
            Input:     -
            Output:    nonce        number        number used once
                       timestamp    float         current time
                       uid          uuid          unique id associated with this message
        '''
        
        # log
        L().log(137, self.sim_env.now , self._ecu_id)
        
        # nonce, timestamp
        nonce, timestamp = self._get_nonce(), self.sim_env.now           
        
        # monitor
        uid = uuid.uuid4()        
        monitor_tag = MonitorTags.CP_ECU_START_CREATION_REG_MESSAGE
        message_id = can_registration.CAN_ECU_AUTH_REG_MSG
        now = self.sim_env.now
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, self._ecu_id, now, self.sec_id, message_id, -1, -1, -1, uid.hex))
        
        # log
        L().log(138, self.sim_env.now , self._ecu_id)
           
        return nonce, timestamp, uid

    
    def _update_taken_nonces(self):
        ''' this updates the valid taken nonces. Every nonce
            is only valid for a certain time frame
            This method finds the next valid time frame
            
            Input:    -
            Output    - 
        '''
        while self.sim_env.now >= self.nonce_valid_till:
            self.taken_nonces = []
            self.nonce_valid_till += self.nonce_validity_time

    
    def _valid_timest_nonce(self, timestamp, received_nonce):
        ''' True if the timestamp and the nonce are both
            valid. Else false
        
            Input:  timestamp        float    time of the received message
                    received_nonce   number   nonce that was received 
            Output: bool             boolean  true if both nonce and timestamp are valid else false  
        '''
        
        # check time
        if timestamp <= self.sim_env.now - self.timestamp_validity:
            return G().val_log_info(False, 123, self.sim_env.now, self._ecu_id)
        
        # check nonce
        if not self._verify_nonce(received_nonce):
            return G().val_log_info(False, 124, self.sim_env.now, self._ecu_id)
        
        return True

    
    def _verify_nonce(self, nonce):
        ''' True if the nonce is valid
    
            Input:    nonce    number    number used once
            Output:   bool    boolean    true if nonce valid
        '''
        return True

    
    def _warn_already_authenticated(self, message_data):
        ''' this method shows a warning that the received advertisement will
            be ignored, because this ECU was already authenticated
        
            Input:    message_data         SegData    received authentication message
            Output:   None 
        '''
        
        # monitor
        monitor_tag = MonitorTags.CP_ECU_ALREADY_AUTHENTICATED
        ecu_id = self._ecu_id
        now = self.sim_env.now
        sender_id = message_data.sender_id
        message_id = can_registration.CAN_ECU_AUTH_ADVERTISE
        message = message_data.get()
        size = len(message_data)
        uid = message_data.unique_id.hex
        G().mon(self.monitor_list, MonitorInput([], monitor_tag, ecu_id, now, sender_id, message_id, message, size, -1, uid)) 
        
        # log
#         logging.warn("ECU %s already authenticated, discarding Sec Module advertisement" % (ecu_id))
        
        return None
