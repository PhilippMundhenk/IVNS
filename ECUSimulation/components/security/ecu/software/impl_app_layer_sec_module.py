import simpy
from components.base.ecu.software.abst_application_layer import AbstractApplicationLayer
from components.security.encryption.public_key_manager import PublicKeyManager
from components.security.encryption import encryption_tools
from components.base.message.abst_bus_message import SegData
from components.security.encryption.encryption_tools import HashedMessage, \
    EncryptionSize
from tools.ecu_logging import ECULogger as L, try_ex
from config import project_registration as proj, can_registration
from config import timing_registration as time
from tools.general import General as G, RefList
from io_processing.surveillance_handler import MonitorInput, MonitorTags
import uuid
import logging

class StdSecurityModuleAppLayer(AbstractApplicationLayer):
    ''' This class is one of the main components of the secure Lightweight authentication
        implementation. It implements the application layer of the Security Module
        that ensures secure connection between various ECUs by managing the allowed 
        communication streams'''

    def __init__(self, sim_env, ecu_id=-1):
        ''' Constructor
            
            Input:  ecu_id         string                   id of the corresponding AbstractECU
                    sim_env        simpy.Environment        environment of this component
            Output:  -
        '''
        AbstractApplicationLayer.__init__(self, sim_env, ecu_id)  

        # project parameters
        self.SSMA_SECM_PUB_ENC_ALG = proj.SSMA_SECM_PUB_ENC_ALG
        self.SSMA_SECM_PUB_ENC_ALG_OPTION = proj.SSMA_SECM_PUB_ENC_ALG_OPTION
        self.SSMA_SECM_PUB_ENC_KEY_LEN = proj.SSMA_SECM_PUB_ENC_KEY_LEN        
        self.SSMA_ECU_AUTH_INTERVAL = proj.SSMA_ECU_AUTH_INTERVAL
        
        # Initializer        
        self.registered_ecus = []
        self.monitor_lst = RefList()
        self._sync = simpy.Store(self.sim_env, capacity=1)  
        self._jitter_in = 1
        
        # Security
        self._init_security(self.SSMA_SECM_PUB_ENC_ALG, self.SSMA_SECM_PUB_ENC_ALG_OPTION, self.SSMA_SECM_PUB_ENC_KEY_LEN)        

        # Complexity reduction
        self._simp_transmit = SimpleTransmitter(ecu_id, sim_env)
        self.ecu_auth = ECUAuthenticator(ecu_id, sim_env, self._private_key, self._public_key, self.monitor_lst, jitter=self._jitter)
        self.stream_auth = StreamAuthorizer(ecu_id, sim_env, self.ecu_auth, self.monitor_lst, jitter=self._jitter)
        
    
    def main(self):
        ''' main entrance point of the application. It starts the main
            receiving process and the process that sends the Security
            Module advertisements.
        
            Input:      -
            Output:     -
        '''

        # security module advertisement
        self.sim_env.process(self._init_ecu_authentication())  

        # receive messages
        self.receive_process = self.sim_env.process(self._main_receive())
                
        # dummy for simpy
        if False: yield self.sim_env.timeout(0)  
        
    
    def register_ecu(self, ecu):
        ''' ECUs that want to participate in a secure communication have
            to be registered via this method. Then necessary information
            between the ECU and the security module are exchanged
            
            Input:   ecu    AbstractECU    ecu that is to be registered to the current security module
            Output:  -
        '''
        
        # add to list
        self.registered_ecus.append(ecu)
        
        # exchange id information
        ecu.ecuSW.comm_mod.sec_mod_id = self._ecu_id
        
        # if ecu set authenticated - pass ecu key
        if ecu.is_authenticated():
            self.ecu_auth.verified_ecu_keys[ecu.ecu_id] = ecu.ecuSW.comm_mod.authenticator.sym_key 
            ecu.ecuSW.comm_mod.changed_sym_key.connect(self._receive_ecu_sym_key)

    
    def _receive_ecu_sym_key(self, id_key_list):
        ''' when the symmetric ECU key of a certain ECU was changed and the ECU was set 
            authenticated the new key is immediately transfered to this security module
        
            Input:     id_key_list    list    list containing the ecu_id that changed its symmertic key and the new symmetric key
            OUtput:     -
        '''
        # extract information
        [ecu_id, sym_key] = id_key_list
        
        # add to ECU keys of security module
        self.ecu_auth.verified_ecu_keys[ecu_id] = sym_key 

    
    def register_ecus(self, ecu_list):
        ''' registers a list of ECUs to the 
            security module.
        
            Input:    ecu_list    list    list of ECUs that will be registered to this security module
            Output:    -     
        '''
        # add to list
        self.registered_ecus = self.registered_ecus + ecu_list
        
        # register
        for ecu in ecu_list:
            self.register_ecu(ecu)

    
    def _init_ecu_authentication(self):
        ''' this method initializes the ECU Authentication process once in the
            defined interval (SSMA_ECU_AUTH_INTERVAL). This is done by sending 
            the initial security module advertisement message
            
            Input:     -
            Output:    -
        '''
        # only triggered if there are any reecivers
        need_send = False
        for ecu in self.registered_ecus:
            if not ecu.is_authenticated():
                need_send = True
        if not need_send: 
            return
        
        while True:
            
            # start authentication
            L().log(0, self.sim_env.now)
            yield self.sim_env.process(self.ecu_auth.trigger_authentication())
            
            # log 
            self._monitor_t('SSMA_ECU_AUTH_INTERVAL')
            G().note_t(str([self._ecu_id, "TRIGGERED_AUTHENTICATION"]), self.sim_env.now)
            
            # wait
            yield self.sim_env.timeout(self.SSMA_ECU_AUTH_INTERVAL)
           
    def _monitor_t(self, variable_string):
        ''' this method adds the monitor input for a timeout that
            was used for the variable given in the variable_string
            Thereby it is assumed that self.'variable_string'
            is the expression for the actual value to be monitored
        
            Input:    variable_string    string    variable that is to be evaluated
            Output:    -
        '''
        var = eval("self.%s" % variable_string)
        G().to_t(self.sim_env, var, variable_string, self.__class__.__name__, self._ecu_id);
            
    
    def _init_security(self, public_enc_algorithm, public_enc_algorithm_option, public_enc_keylength):  
        ''' initializes variables that are needed for the security process of
            the communication
            
            Input:    public_enc_algorithm            AsymAuthMechEnum        public algorithm used for keys that were exchanged with ECUs prior to the communication
                      public_enc_algorithm_option     string/integer/...      option for the public algorithm used for keys that were exchanged with ECUs prior to the communication (e.g. with RSA: set exponent size 3 or 5 or other)
                      public_enc_keylength            AuKeyLengthEnum         key length of algorithm used for keys that were exchanged with ECUs prior to the communication
            Output:    -
        '''   
        
          
        self._lst_root_certificates = []
        self._public_enc_algorithm = public_enc_algorithm
        self._public_enc_algorithm_option = public_enc_algorithm_option
        self._public_enc_keylength = public_enc_keylength
        self._private_key, self._public_key = encryption_tools.asy_get_key_pair(self._public_enc_algorithm, self._public_enc_keylength, self._public_enc_algorithm_option)
        self._key_manage = PublicKeyManager()
        self._key_manage.add_key(self._ecu_id, self._public_key)  # resembles information that was exchanged between ECU and the Sec Module prior to communication
        
    
    def _main_receive(self):
        ''' this method receives messages from the communication module and
            categorizes them according to their message identifier. Possible
            categories are messages for ECU Authentication and messages for the
            stream authorization
            
            Input:     -
            Output:    -
        '''

        while True:
            
            try:
                # receive message
                [self.msg_id, self.msg_data] = yield self.sim_env.process(self._simp_transmit.simple_receive())
                
                # ecu authentication
                if self.msg_id in can_registration.ECU_AUTH_MESSAGES:
                    yield self.sim_env.process(self.ecu_auth.receive_msg(self.msg_id, self.msg_data))
   
                # stream authorization             
                if self.msg_id in can_registration.STREAM_AUTH_MESSAGES:
                    yield self.sim_env.process(self.stream_auth.receive_msg(self.msg_id, self.msg_data))
    
            except simpy.Interrupt:
                L().log_err(1)
                L().log_traceback()

    @property
    
    def public_enc_algorithm_option(self):
        return self._public_enc_algorithm_option
                    
    @public_enc_algorithm_option.setter
    
    def public_enc_algorithm_option(self, value):
        self._public_enc_algorithm_option = value        
        self._private_key, self._public_key = encryption_tools.asy_get_key_pair(self._public_enc_algorithm, self._public_enc_keylength, self.public_enc_algorithm_option)     
                       
        self._key_manage.add_key(self._ecu_id, self._public_key)
        self.ecu_auth.asy_priv_key = self._private_key
        self.ecu_auth.SSMA_SECM_PUB_ENC_ALG_OPTION = value

    @property
    
    def public_enc_algorithm(self):
        return self._public_enc_algorithm
                    
    @public_enc_algorithm.setter
    
    def public_enc_algorithm(self, value):
        
        self._public_enc_algorithm = value        
        self._private_key, self._public_key = encryption_tools.asy_get_key_pair(self._public_enc_algorithm, \
                                                                          self._public_enc_keylength, self.public_enc_algorithm_option)     
                       
        self._key_manage.add_key(self._ecu_id, self._public_key)
        self.ecu_auth.asy_priv_key = self._private_key
        self.ecu_auth.SSMA_SECM_PUB_ENC_ALG = value
      
    @property
    @try_ex
    def public_enc_keylength(self):
        return self._public_enc_keylength
                    
    @public_enc_keylength.setter
    @try_ex
    def public_enc_keylength(self, value):
        self._public_enc_keylength = value
        self._private_key, self._public_key = encryption_tools.asy_get_key_pair(self._public_enc_algorithm, \
                                                                          self._public_enc_keylength, self.public_enc_algorithm_option)                    

        self._key_manage.add_key(self._ecu_id, self._public_key)
        self.ecu_auth.asy_priv_key = self._private_key
        self.ecu_auth.SSMA_SECM_PUB_ENC_KEY_LEN = value
        
    @property
    
    def ecu_id(self):
        return self._ecu_id
    
    @ecu_id.setter
    
    def ecu_id(self, value):
        self._ecu_id = value
        self.ecu_auth.ecu_id = value
        self._simp_transmit.ecu_id = value    
        self.stream_auth.ecu_id = value 

    @property
    
    def comm_mod(self):
        return self._comm_mod 
    
    @comm_mod.setter
    
    def comm_mod(self, value):
        self._simp_transmit.comm_mod = value
        self.ecu_auth.comm_mod = value
        self.stream_auth.comm_mod = value
        self._comm_mod = value

    @property
    
    def _jitter(self):
        return self._jitter_in
    
    @_jitter.setter
    
    def _jitter(self, val):
        try:
            self.ecu_auth._jitter = val
            self.stream_auth._jitter = val
        except:
            pass
        self._jitter_in = val

    @property
    
    def lst_root_certificates(self, value):
        return self._lst_root_certificates 
    
    @lst_root_certificates.setter
    
    def lst_root_certificates(self, value):
        self.ecu_auth.lst_root_certificates = value
        self._lst_root_certificates = value

    
    def monitor_update(self):
        
        items_1 = self.comm_mod.transp_lay.datalink_lay.controller.receive_buffer.get_bytes()
        items_2 = self.comm_mod.transp_lay.datalink_lay.controller.transmit_buffer.get_bytes()
        
        G().mon(self.monitor_lst, MonitorInput(items_1, MonitorTags.BT_ECU_RECEIVE_BUFFER, \
                                               self._ecu_id, self.sim_env.now))
        G().mon(self.monitor_lst, MonitorInput(items_2, MonitorTags.BT_ECU_TRANSMIT_BUFFER, \
                                               self._ecu_id, self.sim_env.now))
                     
        self.monitor_lst.clear_on_access()  # on the next access the list will be cleared        
        return self.monitor_lst.get()

class ECUAuthenticator(object):
    ''' This class handles the ecu authentication process on the security
        module side. Messages meant for this class are forwarded by the 
        StdSecurityModuleAppLayer class. '''
    
    def __init__(self, ecu_id, sim_env, private_key, public_key, monitor_lst=[], jitter=1):
        ''' Constructor
            
            Input:  ecu_id         string                   id of the corresponding AbstractECU
                    sim_env        simpy.Environment        environment of this component
                    private_key    AsymmetricKey            private key that was exchanged with ECUs prior to the communication      
                    public_key     AsymmetricKey            public key that was exchanged with ECUs prior to the communication      
                    monitor_lst    RefList                  monitor list that is used to forward information to the monitor
                    jitter         float                    value that is multiplied on each timeout within this ECU
            Output:  -
        '''

        # Initializations
        self.sim_env = sim_env  
        self.ecu_id = ecu_id
        self.comm_mod = None
        self.monitor_lst = monitor_lst
        self._jitter = jitter
        
        # Security 
        self.certificate = None  # Certificate proving identity of Security Module
        self.asy_priv_key = private_key  # private Key to the public key that was exchanged with ECUs prior to the communication
        self.verified_ecu_keys = {}  # Dictionary of verified symmetric keys between an ecu and the Sec Module
        self.lst_root_certificates = []  # List of Root Certificates
        self.timestamp_validity = 9999999999
        self._key_man = PublicKeyManager()  # resembling Public Keys exchanged with ECUs prior to the communication 
        
        # Timing Parameter 
        self._init_parameters()
      
    
    def receive_msg(self, received_message_id, received_message_data):
        ''' handles messages that were received during the 
            ECU Authentication process
            
            Input:    received_message_id        integer    message id of the received message
                      received_message_data      SegData    content of the  message that was received
            Output:    -
        '''
        
        # received registration message
        if received_message_id == can_registration.CAN_ECU_AUTH_REG_MSG:            
            yield self.sim_env.process(self._handle_registration_message(received_message_data))
        
    
    def trigger_authentication(self):
        ''' this method initializes the authentication process by sending an
            security module advertisement to all ECUs on the bus
            
            Input:    -
            Output:   -
        '''
        
        # Information
        L().log(1, self.sim_env.now, self.ecu_id, can_registration.CAN_ECU_AUTH_ADVERTISE)
        
        # timeout
        if self._monitor_t_ok('SSMA_TRIGGER_AUTH_PROCESS_T'): yield self.sim_env.timeout(self.SSMA_TRIGGER_AUTH_PROCESS_T)
        
        # create message
        auth_msg = SegData(self.certificate, self.SSMA_SECM_CERT_SIZE)
        
        # Monitor
        self._monitor_cp([], MonitorTags.CP_SEC_INIT_AUTHENTICATION, -1, can_registration.CAN_ECU_AUTH_ADVERTISE, self.certificate, self.SSMA_SECM_CERT_SIZE, -1, auth_msg.unique_id.hex)
        
        # Send message
        G().note_sz(str([self.ecu_id, 'SSMA_SECM_CERT_SIZE']), self.SSMA_SECM_CERT_SIZE) 
        yield self.sim_env.process(self.comm_mod.send_msg(self.ecu_id, can_registration.CAN_ECU_AUTH_ADVERTISE, auth_msg)) 

    
    def _cipher_size_registration_message(self, first, ecu_certificate, received_message_data):
        ''' this method calculates the size of the first part of the received registration message.
            It also logs the information to the monitor and the log output
        
            Input:    first:                    EncryptedMessage        first part of the registration message
                      ecu_certificate           ECUCertificate          certificate received from the sending ecu
                      received_message_data     SegData                 raw registration message in shape of a SegData object
            Output:   cipher_size               float                   size of the cipher i.e. size of the first part of the registration message
        '''
        
        # determine the cipher size        
        cipher_size = G().call_or_const(self.SSMA_REG_MSG_CIPHER_SIZE_INNER, self.SSMA_REG_MSG_CT_SIZE_INNER, self.SSMA_SECM_PUB_ENC_ALG, self.SSMA_SECM_PUB_ENC_KEY_LEN, 'ENCRYPTION')    
        
        # monitor checkpoint
        monitor_tag = MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE
        message_id = can_registration.CAN_ECU_AUTH_REG_MSG
        unique_id = received_message_data.unique_id.hex
        self._monitor_cp([], monitor_tag, ecu_certificate.user_id, message_id, first, cipher_size, -1, unique_id)
        
        # log cipher size 
        L().log_debug(3, self.ecu_id, self.sim_env.now); 
        L().log(903, self.sim_env.now, self.ecu_id, first, cipher_size)
        G().note_sz(str([self.ecu_id, 'SSMA_REG_MSG_CIPHER_SIZE_INNER']), cipher_size)
        
        # return size
        return cipher_size
    
    
    def _cipher_sizes_registration_message(self):
        ''' this method calculates the sizes of the registration message
        
            Input:     -
            Output:    cipher_size_inner      float    size of the first part of the registration message cipher
                       cipher_size_outter     float    size of the second part of the registration message cipher
        '''
        # first part
        cipher_size_inner = G().call_or_const(self.SSMA_REG_MSG_CIPHER_SIZE_INNER, self.SSMA_REG_MSG_CT_SIZE_INNER, self.SSMA_SECM_PUB_ENC_ALG, self.SSMA_SECM_PUB_ENC_KEY_LEN, 'ENCRYPTION') 
        
        # second part    
        hashed_size = G().call_or_const(self.SCCM_ECU_REG_MSG_HASH_LEN, self.SSMA_REG_MSG_CT_SIZE_INNER, self.SCCM_ECU_REG_MSG_HASH, None, 'HASH') 
        cipher_size_outter = G().call_or_const(self.SSMA_REG_MSG_CIPHER_SIZE_OUTER, hashed_size, self.SCCM_ECU_PUB_ENC_ALG, self.SCCM_ECU_PUB_ENC_KEY_LEN, 'SIGN')     
        
        # log sizes   
        G().note_sz(str([self.ecu_id, 'SCCM_ECU_REG_MSG_HASH_LEN']), hashed_size)         
        G().note_sz(str([self.ecu_id, 'SSMA_REG_MSG_CIPHER_SIZE_OUTER']), cipher_size_outter) 
        
        return cipher_size_inner, cipher_size_outter 
    
    
    def _decrypt_registration_message(self, received_message_data, time_val_first, time_val_second):
        ''' decrypts the registration message that was received from a certain ECU. This     
            message was encrypted in three steps. 
            The first part was encrypted using the public key of the security module and is
            therefore decrypted here using the private key of the security module.
            The second part was encrypted using the private key of the ECU that was sending it
            and can therefore be decrypted using the public key of the ECU that can be 
            accessed by the security module. The resulting hash inside the decrypted message
            will then be compared to another hash that is generated with the same input.
            The last part of this message contains the certificate of the sending ECU and 
            can therefore be used to verify the ECU s authenticity 
            
            Input:  received_message_data    SegData    raw registration message in shape of a SegData object
                    time_val_first           float      this is the time it takes to decrypt the first part of the message        
                                                        (this constellation was chosen to keep the number of created processes low)
                    time_val_second           float     this is the time it takes to decrypt/verify the second part of the message        
                                                        (this constellation was chosen to keep the number of created processes low)    
            Output:  -
        '''

        # extract
        first, middle, ecu_certificate = received_message_data.get()
        
        # first part
        self._cipher_size_registration_message(first, ecu_certificate, received_message_data)        
        clear_message = encryption_tools.asy_decrypt(first, self.asy_priv_key, received_message_data)  
        
        # first part log
        self._log_first_registration_message(clear_message, ecu_certificate, received_message_data, time_val_first)
        
        # second part
        hashed_size = self._hash_size_second_registration_message(time_val_first, middle)        
        hashed_second = encryption_tools.asy_decrypt(middle, self._key_man.pub_key[ecu_certificate.user_id])
        
        # second part log
        self._log_second_registration_message(time_val_first, time_val_second, hashed_second, hashed_size, ecu_certificate, received_message_data)
        
        # return decrypted information                
        return [ecu_certificate] + clear_message[::-1] + [hashed_second]
        
    
    def _decrypt_registration_message_timeouts(self):
        ''' this method calculates all timeouts that are needed during the 
            decryption of the registration message. This includes the time to 
            decrypt the first part and the second part of the registration message.
            
            Input:      -
            Output:     time_val_first     float        time it takes to decrypt the first part of the registration message
                        time_val_second    float        time it takes to decrypt the second part of the registration message
        '''
        
        # calculate cipher sizes
        cipher_size_inner, cipher_size_outter = self._cipher_sizes_registration_message()         
         
        # calculate time for decryption
        time_val_first, time_val_second = self._timeouts_registration_message(cipher_size_inner, cipher_size_outter)
    
        # add jitter
        return time_val_first * self._jitter, time_val_second * self._jitter
    
    
    def _log_handle_registration_message(self, received_msg_data, time_val_first_second, t_valid_cert, t_cmp_hash, t_hash_reg):
        ''' this method logs the information for the handling of the registration message
            
            Input:  received_msg_data        SegData    raw registration message in shape of a SegData object
                    time_val_first_second    float      time for decryption of the first and second part of the registration message
                    t_valid_cert             float      time to validate the ecu certificate
                    t_cmp_hash               float      time to compare the hash of the second part of the registration message
                    t_hash_reg               float      time to create the hash that is used for the comparison of the second part of the
                                                        registration message
            Output: -
        '''
        # log
        L().log(902, self.sim_env.now, self.ecu_id, received_msg_data.get(), len(received_msg_data))
        L().log(5, self.sim_env.now, self.ecu_id)
    
        # monitor
        variables = 'SSMA_DECR_INNER_REG_MSG + SSMA_DECR_OUTTER_REG_MSG+SSMA_HASH_CMPR_REG_MSG+SSMA_CREATE_CMP_HASH_REG_MSG+SSMA_VALID_CERT_REG_MSG'
        G().to_t(self.sim_env, (time_val_first_second + t_valid_cert + t_cmp_hash + t_hash_reg), variables, self.__class__.__name__, self.ecu_id)
    
    
    def _handle_registration_message(self, received_msg_data):
        ''' This method processes the received registratoin message. Therefor
            it validates the data, stores the symmetric key of the ECU that
            is contained in the message and answers with a confirmation message
            if the validation was successful
        
            Input:    received_msg_data        SegData    raw registration message in shape of a SegData object
            Output:    -
        '''

        # message decryption
        time_val_first, time_val_sec = self._decrypt_registration_message_timeouts()  
        clear_data = self._decrypt_registration_message(received_msg_data, time_val_first, time_val_sec)  
        [ecu_cert, timestamp, nonce, ecu_sym_key, ecu_id, hashed_second] = clear_data
        
        # message validation EcuCertificate
        t_valid_cert, t_cmp_hash, t_hash_reg = self._valid_registration_message_timeouts(ecu_cert.size)
        t = [t_valid_cert, t_cmp_hash, t_hash_reg, time_val_first + time_val_sec]; uid = received_msg_data.unique_id
        valid = self._valid_registration_message(timestamp, ecu_cert, ecu_id, hashed_second, ecu_sym_key, nonce, uid, t[0], t[1], t[2], t[3])
        
        # log
        self._log_handle_registration_message(received_msg_data, t[3], t[0], t[1], t[2])
        
        # timeout
        yield self.sim_env.timeout((time_val_first + time_val_sec + t_valid_cert + t_cmp_hash + t_hash_reg))
        
        # store key and send confirmation
        if valid: 
            self._store_ecu_symmetric_key(ecu_cert, ecu_sym_key)
            yield self.sim_env.process(self._send_confirmation_msg(ecu_cert, nonce, ecu_sym_key))
    
    
    def _hash_size_second_registration_message(self, time_val_first, middle):
        ''' this method calculates the hashed size and the cipher size of the second part of the 
            registration message and returns it. Add the same time relevant
            process steps are logged
        
            Input:  time_val_first    float               time the first part of the processing of the registration message took
                    middle            EncryptedMessage    second part of the registration message as encrypted message
            Ouput:  hashed_size       float               size of the decrypted seconf part of the registration message i.e. the hash size
        '''
        
        # hash size             
        hashed_size = G().call_or_const(self.SCCM_ECU_REG_MSG_HASH_LEN, self.SSMA_REG_MSG_CT_SIZE_INNER, self.SCCM_ECU_REG_MSG_HASH, None, 'HASH')
        
        # log hash size
        L().log_debug(4, self.ecu_id, self.sim_env.now + time_val_first)           
        G().note_sz(str([self.ecu_id, 'SCCM_ECU_REG_MSG_HASH_LEN']), hashed_size) 
        
        # cipher size
        cipher_size = G().call_or_const(self.SSMA_REG_MSG_CIPHER_SIZE_OUTER, hashed_size, self.SCCM_ECU_PUB_ENC_ALG, self.SCCM_ECU_PUB_ENC_KEY_LEN, 'SIGN')
        
        # log cipher size 
        G().note_sz(str([self.ecu_id, 'SSMA_REG_MSG_CIPHER_SIZE_OUTER']), cipher_size)  
        L().log(905, self.sim_env.now + time_val_first, self.ecu_id, middle, cipher_size)        
        
        # return hash size
        return hashed_size
    
    
    def _init_parameters(self):
        ''' Initializes all project and timing parameters with the
            settings as they are set in the project file project.ini
        
            Input:    -
            Output:   -
        '''        
        
        # timing
        self.SSMA_TRIGGER_AUTH_PROCESS_T = time.SSMA_TRIGGER_AUTH_PROCESS_T
        self.SSMA_DECR_INNER_REG_MSG = time.SSMA_DECR_INNER_REG_MSG
        self.SSMA_DECR_OUTTER_REG_MSG = time.SSMA_DECR_OUTTER_REG_MSG
        self.SSMA_ENCR_CONF_MSG_ECU_KEY = time.SSMA_ENCR_CONF_MSG_ECU_KEY
        self.SSMA_VALID_CERT_REG_MSG = time.SSMA_VALID_CERT_REG_MSG
        self.SSMA_CREATE_CMP_HASH_REG_MSG = time.SSMA_CREATE_CMP_HASH_REG_MSG
        self.SSMA_HASH_CMPR_REG_MSG = time.SSMA_HASH_CMPR_REG_MSG

        # project Parameters
        self.SSMA_SECM_CERT_SIZE = proj.SSMA_SECM_CERT_SIZE
        self.SSMA_SECM_CONF_MSG_SIZE = proj.SSMA_SECM_CONF_MSG_SIZE
        self.SCCM_ECU_REG_MSG_HASH = proj.SCCM_ECU_REG_MSG_HASH
        self.SSMA_REG_MSG_CIPHER_SIZE_INNER = proj.SSMA_REG_MSG_CIPHER_SIZE_INNER
        self.SSMA_REG_MSG_CIPHER_SIZE_OUTER = proj.SSMA_REG_MSG_CIPHER_SIZE_OUTER
        self.SSMA_REG_MSG_CT_SIZE_INNER = proj.SSMA_REG_MSG_CT_SIZE_INNER        
        self.SSMA_SECM_PUB_ENC_ALG = proj.SSMA_SECM_PUB_ENC_ALG
        self.SSMA_SECM_PUB_ENC_ALG_OPTION = proj.SSMA_SECM_PUB_ENC_ALG_OPTION
        self.SSMA_SECM_PUB_ENC_KEY_LEN = proj.SSMA_SECM_PUB_ENC_KEY_LEN        
        self.SCCM_ECU_PUB_ENC_ALG = proj.SCCM_ECU_PUB_ENC_ALG
        self.SCCM_ECU_PUB_ENC_ALG_OPTION = proj.SCCM_ECU_PUB_ENC_ALG_OPTION
        self.SCCM_ECU_PUB_ENC_KEY_LEN = proj.SCCM_ECU_PUB_ENC_KEY_LEN
        self.SCCM_ECU_REG_MSG_HASH_LEN = proj.SCCM_ECU_REG_MSG_HASH_LEN                
                
        self.ECU_CERT_HASHING_MECH = proj.ECU_CERT_HASHING_MECH
        self.ECU_CERT_ENCRYPTION_MECH = proj.ECU_CERT_ENCRYPTION_MECH
        self.ECU_CERT_ENCRYPTION_MECH_OPTION = proj.ECU_CERT_ENCRYPTION_MECH_OPTION
        self.ECU_CERT_KEYL = proj.ECU_CERT_KEYL
        self.ECU_CERT_CA_LEN = proj.ECU_CERT_CA_LEN
        self.ECU_CERT_SIZE_HASH_TO_SIGN = proj.ECU_CERT_SIZE_HASH_TO_SIGN
        self.ECU_CERT_SIZE_HASH = proj.ECU_CERT_SIZE_HASH        
        self.SCCM_ECU_CONF_MSG_SIZE = proj.SCCM_ECU_CONF_MSG_SIZE
    
    
    def _log_first_registration_message(self, clear_message, ecu_certificate, received_message_data, time_val_first):
        ''' this method logs the checkpoints and sizes for the end of the first registration 
            message 
        
            Input:    clear_message             list                    decrypted message that was received from the first part of the registration message
                      ecu_certificate           ECUCertificate          certificate received from the sending ecu
                      received_message_data     SegData                 raw registration message in shape of a SegData object
                      time_val_first            time                    time to decrypt the first registration message part
            Output:    -        
        '''
        
        # log information
        L().log(904, self.sim_env.now, self.ecu_id, clear_message, self.SSMA_REG_MSG_CT_SIZE_INNER)
        
        # monitor checkpoint
        monitor_tag = MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE
        message_id = can_registration.CAN_ECU_AUTH_REG_MSG
        unique_id = received_message_data.unique_id.hex
        size = self.SSMA_REG_MSG_CT_SIZE_INNER
        self._monitor_cp([], monitor_tag, ecu_certificate.user_id, message_id, clear_message, size, -1, unique_id, time_val_first) 
        
        # note message size
        G().note_sz(str([self.ecu_id, 'SSMA_REG_MSG_CT_SIZE_INNER']), self.SSMA_REG_MSG_CT_SIZE_INNER) 
    
    
    def _log_second_registration_message(self, time_val_first, time_val_second, hashed_second, hashed_size, ecu_certificate, received_message_data):
        ''' this method logs the checkpoints and sizes for the end of the second registration 
            message 
            
            Input:    time_val_first            float                  this is the time it takes to decrypt the first part of the message        
                                                                       (this constellation was chosen to keep the number of created processes low)
                      time_val_second           float                  this is the time it takes to decrypt the second part of the message       
                      hashed_second             HashedMessage          hashed message: i.e. the decrypted second part of the registration message 
                      hashed_size               float                  size of the decrypted second part of the registration message
                      ecu_certificate           ECUCertificate         certificate received from the sending ecu
                      received_message_data     SegData                raw registration message in shape of a SegData object
        '''
        
        # log
        L().log(906, self.sim_env.now + time_val_first + time_val_second, self.ecu_id, hashed_second, hashed_size)
        
        # monitor
        monitor_tag = MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE
        time = self.sim_env.now + time_val_first + time_val_second
        asc_id = ecu_certificate.user_id
        msg_id = can_registration.CAN_ECU_AUTH_REG_MSG
        unique_id = received_message_data.unique_id.hex
        
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, time, asc_id, msg_id, hashed_second, hashed_size, -1, unique_id))
    
    
    def _monitor_cp(self, data, monitor_tag, asc_id=None, message_id=-1, message=None, message_size=-1, stream_id=-1, unique_id=None, time_val=0):
        ''' this method adds a MonitorInput to the monitor list that has 
            already predefined the ecu_id and the time called
        
            Input:  data            object        data to be transmitted to the monitor
                    monitor_tag     MonitorTag    defines which Handler will receive this input
                    asc_id          string        identifier of the component that is associated with the component for this MonitorInput
                    message_id      integer       message identifier of the input that is passed to the Monitor
                    message         object        content of the message that was monitored
                    message_size    float         size of the message that was monitored
                    stream_id       integer       identifier of the stream that is associated with this Monitor Input
                    unique_id       hex           identifier that is used to find the connection between two MonitorInputs that are meant to be read together
                    time_val        float         optional time that will be added on current time
            Output:    -
        '''
        G().mon(self.monitor_lst, MonitorInput(data, monitor_tag, self.ecu_id, self.sim_env.now + time_val, asc_id, message_id, message, message_size, stream_id, unique_id))

    
    def _monitor_t_ok(self, variable_string, val=False, jitter=False):
        ''' this method adds the monitor input for a timeout that
            was used for the variable given in the variable_string
            Thereby it is assumed that self.'variable_string'
            is the expression for the actual value to be monitored
        
            Input:    variable_string    string    variable that is to be evaluated
            Output:   bool               boolean    true if this variable is not 0
        '''
        var = eval("self.%s" % variable_string)
        if var == 0: return False
        
        if val: var = val
        if jitter: var *= self._jitter 
        
        G().to_t(self.sim_env, var, variable_string, self.__class__.__name__, self.ecu_id);
        return True
    
    
    def _send_confirmation_msg(self, ecu_certificate, nonce, ecu_symmetric_key):
        ''' this message sends a confirmation message to the respective ECU 
            after having received it's corresponding registration message from 
            
            Input:  ecu_certificate    ECUCertificate    certificate received from the registration message
                    nonce              number            number used once received in the registration message
                    ecu_symmetric_key  SymmetricKey      symmetric key received from the registration message 
                                                          (used to exchange data with ECU)
            Output: -
        '''
        
        # encryption time
        time_val = self._time_encryption_confirmation_message(ecu_certificate, ecu_symmetric_key)
        yield self.sim_env.timeout(time_val * self._jitter)         
        
        # encrypt
        clear_message = [ecu_certificate.user_id, nonce, self.sim_env.now]
        encrypted_message = encryption_tools.sym_encrypt(clear_message, ecu_symmetric_key)
        
        # confirmation message
        message_id = can_registration.CAN_ECU_AUTH_CONF_MSG
        message_size = self._sending_size_confirmation_message(ecu_certificate, nonce, ecu_symmetric_key, encrypted_message)        
        message = SegData(encrypted_message, message_size)

        # Monitor
        monitor_tag = MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE
        asc_id = ecu_certificate.user_id        
        self._monitor_cp([], monitor_tag, asc_id, message_id, encrypted_message, message_size, -1, message.unique_id.hex)
        
        # send message
        yield self.sim_env.process(self.comm_mod.send_msg(self.ecu_id, message_id, message)) 
    
    
    def _sending_size_confirmation_message(self, ecu_certificate, nonce, ecu_symmetric_key, encrypted_message):
        ''' this method calculates the sending size of the confirmation message
            and logs further information
            
            Input:  ecu_certificate    ECUCertificate     certificate received from the registration message
                    nonce              number             number used once received in the registration message
                    ecu_symmetric_key  SymmetricKey       symmetric key received from the registration message 
                    encrypted_message  EncryptedMessage   encrypted confirmation message that will be sent to the receiver ECU 
            Output: - 
        '''
        # log 
        L().log(915, self.sim_env.now, self.ecu_id, ecu_certificate.user_id, [ecu_certificate.user_id, nonce, self.sim_env.now], self.SCCM_ECU_CONF_MSG_SIZE) 
        
        # calculate size
        sending_size = G().call_or_const(self.SSMA_SECM_CONF_MSG_SIZE, self.SCCM_ECU_CONF_MSG_SIZE, ecu_symmetric_key.valid_alg, ecu_symmetric_key.valid_key_len, 'ENCRYPTION')  
        
        # log size
        G().note_sz(str([self.ecu_id, 'SSMA_SECM_CONF_MSG_SIZE']), sending_size) 
        L().log(916, self.sim_env.now, self.ecu_id, ecu_certificate.user_id, encrypted_message, sending_size) 
    
        return sending_size
    
    
    def _time_encryption_confirmation_message(self, ecu_certificate, ecu_symmetric_key):
        ''' this method returns the time it takes to encrypt the confirmation 
            message using the symmetric key from the registration message
        
            Input:  ecu_certificate    ECUCertificate    certificate received from the registration message                   
                    ecu_symmetric_key  SymmetricKey      symmetric key received from the registration message 
                                                          (used to exchange data with ECU)
            Output: -
        '''
        # extract information 
        algorithm = ecu_symmetric_key.valid_alg
        algorithm_mode = ecu_symmetric_key.valid_alg_mode
        key_length = ecu_symmetric_key.valid_key_len
        
        # log size
        L().log(7, self.sim_env.now, self.ecu_id, ecu_certificate.user_id) 
        G().note_sz(str([self.ecu_id, 'SCCM_ECU_CONF_MSG_SIZE']), self.SCCM_ECU_CONF_MSG_SIZE) 
        
        # calculate time
        time_val = time.call(self.SSMA_ENCR_CONF_MSG_ECU_KEY, self.SCCM_ECU_CONF_MSG_SIZE, algorithm, key_length, algorithm_mode)  
        
        # log time
        self._monitor_t_ok('SSMA_ENCR_CONF_MSG_ECU_KEY', time_val, True)
        
        return time_val
    
    
    def _same_hashes_registration_message(self, hashed_second, pre_t, t_valid_cert, t_cmp_hash, clear_message, ecu_certificate, uid):
        ''' This method compares the hash that was decrypted from the second part of the registration message
            to the hash that was build from the expected clear message. This ensures that the message
            was not modified
        
            Input:  hashed_second       HashedMessage        decrypted second part of the registration message i.e. a hashed message
                    clear_message       float                expected message to be hashed: [ecu_id, ecu_sym_key, nonce, timestamp]
                    ecu_certificate     ECUCertificate       ecu certificate sent with the registration message                     
                    uid                 uuid                 unique id associated with this registration message
                    t_valid_cert        float                time to validate the ECU certificate
                    t_cmp_hash          float                time to compare the hashes of the second registration message                    
                    pre_t               float                time to decrypt the first and the second part of the registration message            
            Output: bool                boolean              true if this registration message is valid
            
        '''       
        # monitor and log
        monitor_tag = MonitorTags.CP_SEC_CREATED_CMP_HASH_REG_MSG
        current_time = self.sim_env.now + pre_t + t_valid_cert
        asc_id = ecu_certificate.user_id
        msg_id = can_registration.CAN_ECU_AUTH_REG_MSG
        L().log(908, current_time, self.ecu_id, clear_message, self.SSMA_REG_MSG_CT_SIZE_INNER)  # t_cmp_hash passed
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, current_time + t_cmp_hash, asc_id, msg_id, "HashedMessage", -1, -1, uid.hex))
        
        # check condition ( t_hash_reg passed)           
        same_hash = hashed_second.same_hash(HashedMessage(clear_message, self.SCCM_ECU_REG_MSG_HASH)) 
        
        # return result
        return same_hash
    
    
    def _signed_size_ecu_certificate(self, ecu_certificate):            
        ''' this method calculates the signed size of the ecu certificate.
            So the size of the signature that needs to be verified.
            
            Input:     ecu_certificate     ECUCertificate       ecu certificate sent with the registration message 
            Output:    signed_size         float                size of the ecu certificate signature
        '''
        
        # size
        signed_size = G().call_or_const(self.ECU_CERT_SIZE_HASH, self.ECU_CERT_SIZE_HASH_TO_SIGN, self.ECU_CERT_ENCRYPTION_MECH, self.ECU_CERT_KEYL, 'SIGN')
        
        # log
        G().note_sz(str([self.ecu_id, 'ECU_CERT_SIZE_HASH_TO_SIGN']), self.ECU_CERT_SIZE_HASH_TO_SIGN) 
        G().note_sz(str([self.ecu_id, 'ECU_CERT_SIZE_HASH']), signed_size) 
        L().log(907, self.sim_env.now, self.ecu_id, ecu_certificate, self.ECU_CERT_SIZE_HASH_TO_SIGN, signed_size)
    
        return signed_size
    
    
    def _store_ecu_symmetric_key(self, ecu_certificate, ecu_symmetric_key):
        ''' stores the symmetric ECU key that was just received from the 
            registration message
        
            Input:  ecu_certificate     ECUCertificate    certificate of the ECU received in the registration message
                    ecu_symmetric_key   SymmetricKey      key that was exchanged between this security module and the sending ECU
            Output: -
        '''
        # log
        L().log(6, self.ecu_id, ecu_certificate, ecu_symmetric_key)           
        
        # store key
        self.verified_ecu_keys[ecu_certificate.user_id] = ecu_symmetric_key 
    
    
    def _timeouts_registration_message(self, cipher_size_inner, cipher_size_outter):
        ''' returns the timeouts for the decryption of the first and the second
            ciphers of the registration message
            
            Input:   cipher_size_inner      float    size of the first part of the registration message cipher
                     cipher_size_outter     float    size of the second part of the registration message cipher
            Output:  time_val_first         float    time for decryption of first part of the registration message cipher
                     time_val_second        float    time for decryption of second part of the registration message cipher
        '''
        
        # first part
        time_val_first = time.call(self.SSMA_DECR_INNER_REG_MSG, self.SSMA_SECM_PUB_ENC_ALG, self.SSMA_SECM_PUB_ENC_KEY_LEN, \
                                   cipher_size_inner, self.SSMA_SECM_PUB_ENC_ALG_OPTION)  
        
        # second part
        time_val_second = time.call(self.SSMA_DECR_OUTTER_REG_MSG, self.SCCM_ECU_PUB_ENC_ALG, \
                                 self.SCCM_ECU_PUB_ENC_KEY_LEN, cipher_size_outter, self.SCCM_ECU_PUB_ENC_ALG_OPTION)
        
        return time_val_first, time_val_second
    
    
    def _validate_ecu_certificate(self, ecu_certificate, pre_t, t_valid_cert, signed_size, uid):
        ''' this method checks if the received certificate is valid
        
            Input:  
                    ecu_certificate     ECUCertificate       ecu certificate sent with the registration message                     
                    uid                 uuid                 unique id associated with this registration message
                    t_valid_cert        float                time to validate the ECU certificate     
                    pre_t               float                time to decrypt the first and the second part of the registration message         
            Output: bool                boolean              true if the ecu certificate is valid
        '''
        
        # check certificate
        current_time = self.sim_env.now + pre_t + t_valid_cert
        condition = encryption_tools.certificate_trustworthy(ecu_certificate, self.lst_root_certificates, current_time)
        
        # monitor
        monitor_tag = MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE
        asc_id = ecu_certificate.user_id
        message_id = can_registration.CAN_ECU_AUTH_REG_MSG
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, current_time, asc_id, message_id, ecu_certificate, signed_size, -1, uid.hex)) 
        
        # return condition
        return condition
        
    
    def _valid_registration_message(self, timestamp, ecu_certificate, ecu_id, hashed_second, ecu_sym_key, nonce, uid, t_valid_cert, t_cmp_hash, t_hash_reg, pre_t):
        ''' this method checks if the received registration message
            is valid
        
            Input:  timestamp           float                timestamp sent with the registration message
                    ecu_certificate     ECUCertificate       ecu certificate sent with the registration message 
                    ecu_id              string               ecu id sending the registration message
                    hashed_second       HashedMessage        decrypted second part of the registration message i.e. a hashed message
                    ecu_symmetric_key   SymmetricKey         symmetric key that was exchanged between the ecu and this security module
                    nonce               float                number used once sent with the registration message
                    uid                 uuid                 unique id associated with this registration message
                    t_valid_cert        float                time to validate the ECU certificate
                    t_cmp_hash          float                time to compare the hashes of the second registration message
                    t_hash_reg          float                time to create the hash for the registration message comparison
                    pre_t               float                time to decrypt the first and the second part of the registration message            
            Output: bool                boolean              true if this registration message is valid
        '''
        try:
            # validate the certificate
            signed_size = self._signed_size_ecu_certificate(ecu_certificate)  # t_valid_cert   passed               
            valid_certificate = self._validate_ecu_certificate(ecu_certificate, pre_t, t_valid_cert, signed_size, uid)
                 
            # compare hashes
            clear_message = [ecu_id, ecu_sym_key, nonce, timestamp]
            hashes_equal = self._same_hashes_registration_message(hashed_second, pre_t, t_valid_cert, t_cmp_hash, clear_message, ecu_certificate, uid)
            
            # verify time stamp
            valid_timestamp = self._verify_timestamp_registration_message(timestamp, pre_t, t_valid_cert, t_cmp_hash, t_hash_reg)
            
            # verify nonce
            current_time = self.sim_env.now + pre_t + t_valid_cert + t_cmp_hash + t_hash_reg
            valid_nonce = self._verify_nonce_registration_message(nonce, current_time, ecu_certificate, signed_size, uid)
            
        except:
            L().log_traceback()
            valid_certificate, hashes_equal, valid_timestamp, valid_nonce = False, False, False, False
        
        # return result
        L().log(8, self.ecu_id, ecu_certificate.user_id, valid_certificate and hashes_equal)
        return (valid_certificate and hashes_equal and valid_timestamp and valid_nonce)

    
    def _valid_registration_message_timeouts(self, cert_size):
        ''' this method returns the timeouts for the registration validation summed up to 
            increase the performance of the system.
            
            Input:     -
            Output:    t_valid_cert        float                time to validate the ECU certificate
                       t_cmp_hash          float                time to compare the hashes of the second registration message
                       t_hash_reg          float                time to create the hash for the registration message comparison 
        '''
        
        # calculate signature size 
        signed_size = G().call_or_const(self.ECU_CERT_SIZE_HASH, self.ECU_CERT_SIZE_HASH_TO_SIGN, self.ECU_CERT_ENCRYPTION_MECH, self.ECU_CERT_KEYL, 'SIGN')
        
        # certificate validation time
        t_valid_cert = time.call(self.SSMA_VALID_CERT_REG_MSG, self.ECU_CERT_HASHING_MECH, self.ECU_CERT_ENCRYPTION_MECH, \
                                 self.ECU_CERT_KEYL, self.ECU_CERT_CA_LEN, self.ECU_CERT_SIZE_HASH_TO_SIGN, signed_size, self.ECU_CERT_ENCRYPTION_MECH_OPTION, cert_size)
        
        # hash creation time
        t_cmp_hash = time.call(self.SSMA_CREATE_CMP_HASH_REG_MSG, self.SSMA_REG_MSG_CT_SIZE_INNER, self.SCCM_ECU_REG_MSG_HASH)
        
        # hash comparison time
        t_hash_reg = self.SSMA_HASH_CMPR_REG_MSG

        # result
        return t_valid_cert * self._jitter, t_cmp_hash * self._jitter, t_hash_reg * self._jitter

    
    def _verify_nonce(self, nonce):
        ''' this method checks if the given nonce is valid or not
            
            Input:  nonce               integer              number used once                       
            Output: bool                boolean              true if the nonceis valid            
        '''
        # TODO: Implement
        return True
    
    
    def _verify_nonce_registration_message(self, nonce, current_time, ecu_certificate, signed_size, uid):
        ''' this method is true if the nonce of the registration message is
            valid
        
            Input:  nonce               integer              number used once
                    current_time        float                current time of the system
                    ecu_certificate     ECUCertificate       ecu certificate sent with the registration message 
                    signed_size         float                size of the certificate signature after signing
                    uid                 uuid                 unique id associated with this registration message                           
            Output: bool                boolean              true if the nonce in this registration message is valid
        '''   
        
        # monitor
        monitor_tag = MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG
        asc_id = ecu_certificate.user_id
        msg_id = can_registration.CAN_ECU_AUTH_REG_MSG
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, current_time, asc_id, msg_id, ecu_certificate, signed_size, -1, uid.hex))   
        
        # verify
        return self._verify_nonce(nonce)
    
    
    def _verify_timestamp_registration_message(self, timestamp, pre_t, t_valid_cert, t_cmp_hash, t_hash_reg):
        ''' this method verifies if the timestamp in the registration message
            is still valid
            
            Input:  timestamp           float                timestamp sent with the registration message                    
                    t_valid_cert        float                time to validate the ECU certificate
                    t_cmp_hash          float                time to compare the hashes of the second registration message
                    t_hash_reg          float                time to create the hash for the registration message comparison
                    pre_t               float                time to decrypt the first and the second part of the registration message            
            Output: bool                boolean              true if the timestamp is valid
            
        '''
        return timestamp >= (self.sim_env.now + pre_t + t_valid_cert + t_cmp_hash + t_hash_reg) - self.timestamp_validity

class StreamAuthorizer(object):
    '''
    this class handles the stream authorization on the security module
    side. All messages that are designated to this part of the communication
    are forwarded to this class by the communication module.    
    '''
    
    def __init__(self, ecu_id, sim_env, ecu_authenticator, monitor_lst=[], jitter=1):   
        ''' Constructor
            
            Input:  ecu_id                 string                   id of the corresponding AbstractECU
                    sim_env                simpy.Environment        environment of this component
                    ecu_authenticator      ECUAuthenticator         ECUAuthenticator that was ran before the Stream authorization
                    monitor_lst            RefList                  monitor list that is used to forward information to the monitor
                    jitter                 float                    value that is multiplied on each timeout within this ECU
            Output:  -
        '''
        
        # initial parameters
        self.sim_env = sim_env  
        self.ecu_id = ecu_id
        self._sync = simpy.Store(self.sim_env, capacity=1)
        self.comm_mod = None
        self.ecu_auth = ecu_authenticator
        self.session_key_validity = 1000
        self.timestamp_validity = 9000
        self.allowed_streams = []  # list of allowed streams in format: [msg_id, [[sender_ecu, [receiver_1, receiver_2,...]], [..]]
        self._already_granted_streams = {}  # streams that were granted once cannot be granted again within the time of its validity (can only be granted anew if the validity of the session key expired)
        self.monitor_lst = monitor_lst
        self._jitter = jitter
                
        # timing parameter
        self.SSMA_STREAM_REQ_INI_DECR = time.SSMA_STREAM_REQ_INI_DECR
        self.SSMA_STREAM_ENC_DENY_MSG = time.SSMA_STREAM_ENC_DENY_MSG
        self.SSMA_SESS_KEYGEN_GRANT_MSG = time.SSMA_SESS_KEYGEN_GRANT_MSG
        self.SSMA_STREAM_ENC_GRANT_MSG = time.SSMA_STREAM_ENC_GRANT_MSG

        # project parameter
        self.SSMA_SECM_SES_KEY_ENC_ALG = proj.SSMA_SECM_SES_KEY_ENC_ALG
        self.SSMA_SECM_SES_KEY_ENC_ALG_MODE = proj.SSMA_SECM_SES_KEY_ENC_ALG_MODE        
        self.SSMA_SECM_SES_KEY_ENC_KEY_LEN = proj.SSMA_SECM_SES_KEY_ENC_KEY_LEN
        self.SSMA_SECM_DENY_MSG_SIZE = proj.SSMA_SECM_DENY_MSG_SIZE
        self.SSMA_SECM_GRANT_MSG_SIZE = proj.SSMA_SECM_GRANT_MSG_SIZE
        self.SSMA_SECM_SES_KEY_VALIDITY = proj.SSMA_SECM_SES_KEY_VALIDITY        
        self.SSMA_GRANT_MSG_CT_SIZE = proj.SSMA_GRANT_MSG_CT_SIZE
        self.SSMA_SIZE_REQ_MSG_CIPHER = proj.SSMA_SIZE_REQ_MSG_CIPHER
        self.SSMA_SIZE_REQ_MSG_CONTENT = proj.SSMA_SIZE_REQ_MSG_CONTENT

    def receive_msg(self, received_message_id, received_message_data):
        ''' this method receives all incoming messages and handles them
        
            Input:    received_message_id        integer    message id of the received message
                      received_message_data      SegData    content of the  message that was received
            Output:    -
        '''
        
        # request message        
        if received_message_id == can_registration.CAN_STR_AUTH_INIT_MSG_STR:               
            yield self.sim_env.process(self._handle_stream_req(received_message_data))               
            
    def _valid_timestamp_and_nonce(self, nonce, timestamp):
        ''' this method checks if the given nonce and the given
            time stamp are valid
        
            Input:    nonce        number    number used once
                      timestamp    float     current point in time
            Output:   bool         boolean   true if both nonce and timestamp are valid 
        '''
        
        # timestamp
        valid_timestamp = timestamp >= self.sim_env.now - self.timestamp_validity
        
        # nonce
        valid_nonce = self._verify_nonce(nonce)
                 
        return (valid_timestamp and valid_nonce)
        
    def _expand_already_granted(self, stream_id, session_key):
        ''' this method remembers the allowed streams and sends 
            it only anew if it became invalid. Else this stream
            request will be ignored
            Thus it garantees that each stream is only granted
            once in a defined time interval
            
            Input:     stream_id    integer         stream id under consideration
                       session_key  SymmetricKey    session key that was generated for this stream
            Output:    -
        
        '''

        # granted already   
        if stream_id in self._already_granted_streams.keys():           
            valid_till = self._already_granted_streams[stream_id]
            
            # request came to early       
            if self.sim_env.now >= valid_till:       
                self._already_granted_streams[stream_id] = session_key.valid_till
                
        # not yet granted
        else:
            self._already_granted_streams[stream_id] = session_key.valid_till
    
    def _timeout_session_key_generation(self, stream_id, sender_id):
        ''' this method returns that time needed to 
            generate the session key for the grant message
            
            Input:    stream_id    integer    id of the stream that is to be sent
                      sender_id    string     id of the receiver that will get the session key
            Output:   time_val     float      time it takes to generate the session key  
                      uid          hex        identifier to label messages whose monitorInputs are to be grouped
        '''
        
        # time value
        time_val = time.call(self.SSMA_SESS_KEYGEN_GRANT_MSG, self.SSMA_SECM_SES_KEY_ENC_ALG, self.SSMA_SECM_SES_KEY_ENC_KEY_LEN)        
        
        # monitor
        monitor_tag = MonitorTags.CP_SEC_GENERATED_SESSION_KEY
        cur_time = self.sim_env.now + time_val * self._jitter
        msg_id = can_registration.CAN_STR_AUTH_GRANT_MSG
        uid = uuid.uuid4()
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, cur_time, sender_id, msg_id, -1, -1, stream_id, uid.hex))
        
        return time_val * self._jitter, uid
        
    def _generate_grant_message(self, session_key, receiver_id, stream_id, nonce, sender_id):
        ''' this message generates the clear grant message
            for the given stream
            
            Input:  session_key    SymmetricKey    symmetric key that was exchanged for this session
                    receiver_id    string          id of the receiver of the grant message
                    stream_id      integer         id of the stream under consideration
                    nonce          number          number used once
                    sender_id      string          id of the ECU that sent the request that is answered
            Output: -  
        '''
        
        # log
        L().log(16, self.ecu_id, session_key, receiver_id)
                
        # create message
        timestamp = self.sim_env.now
        clear_message = [receiver_id, stream_id, session_key, nonce, timestamp, sender_id]
        
        # log
        L().log(912, self.sim_env.now, self.ecu_id, receiver_id, stream_id, clear_message, self.SSMA_GRANT_MSG_CT_SIZE)     
        
        # return message
        return clear_message
    
    
    def _timeout_deny_message_encryption(self, receiver_id, decrypted_message):
        ''' returns the time it takes to encrypt the deny message
            aimed at receiver with id receiver_id
        
            Input:    receiver_id        string        identifier of the receiver
                      decrypted_message  list          decrypted request message
            Output:   time_val           float         time it takes to encrypt the deny message
        '''
        
        # extract
        algorithm = self.ecu_auth.verified_ecu_keys[receiver_id].valid_alg
        algorithm_mode = self.ecu_auth.verified_ecu_keys[receiver_id].valid_alg_mode
        key_length = self.ecu_auth.verified_ecu_keys[receiver_id].valid_key_len
        
        # log
        L().log(917, self.sim_env.now, self.ecu_id, decrypted_message[1], decrypted_message[0]); 
        G().note_sz(str([self.ecu_id, 'SSMA_DENY_MSG_CT_SIZE']), self.SSMA_GRANT_MSG_CT_SIZE) 
        
        # calculate time
        time_val = time.call(self.SSMA_STREAM_ENC_DENY_MSG, algorithm, key_length, self.SSMA_GRANT_MSG_CT_SIZE, algorithm_mode) * self._jitter 
        
        # log     
        G().to_t(self.sim_env, time_val, 'SSMA_STREAM_ENC_DENY_MSG', self.__class__.__name__, self.ecu_id)
    
        return time_val, uuid.uuid4().hex
        
    
    def _timeout_grant_message_encryption(self, receiver_id):
        ''' returns the time it takes to encrypt the grant message
            aimed at receiver with id receiver_id
        
            Input:    receiver_id    string        identifier of the receiver
            Output:   time_val       float         time it takes to encrypt the grant message
        '''
        
        # extract
        algorithm = self.ecu_auth.verified_ecu_keys[receiver_id].valid_alg
        key_length = self.ecu_auth.verified_ecu_keys[receiver_id].valid_key_len
        algorithm_mode = self.ecu_auth.verified_ecu_keys[receiver_id].valid_alg_mode
        
        # note size
        G().note_sz(str([self.ecu_id, 'SSMA_GRANT_MSG_CT_SIZE']), self.SSMA_GRANT_MSG_CT_SIZE)
        
        # calculate timeout
        time_val = time.call(self.SSMA_STREAM_ENC_GRANT_MSG, algorithm, key_length, self.SSMA_GRANT_MSG_CT_SIZE, algorithm_mode)
        
        # log
        G().to_t(self.sim_env, time_val , 'SSMA_GRANT_MSG_CT_SIZE', self.__class__.__name__, self.ecu_id)
        
        # return time        
        return time_val * self._jitter
    
    def size_grant_message_encrypted(self, receiver_id, stream_id, clear_message):
        ''' returns the size of the grant message after being encrypted
            with the respective ECU key
            
            Input:    receiver_id    string     id of the target ECU
                      stream_id      integer    stream that is to be granted
                      clear_message  list       clear grant message
            Output:    -                       
        '''    
            
        sending_size = G().call_or_const(self.SSMA_SECM_GRANT_MSG_SIZE, self.SSMA_GRANT_MSG_CT_SIZE, \
                                         self.ecu_auth.verified_ecu_keys[receiver_id].valid_alg, \
                                         self.ecu_auth.verified_ecu_keys[receiver_id].valid_key_len, 'ENCRYPTION')  
        G().note_sz(str([self.ecu_id, 'SSMA_SECM_GRANT_MSG_SIZE']), sending_size)
        L().log(913, self.sim_env.now, self.ecu_id, receiver_id, stream_id, 'Encrypted Message', sending_size)
        
        # Monitor
        uid = uuid.uuid4()              
        G().mon(self.monitor_lst, MonitorInput([], MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE, self.ecu_id, self.sim_env.now, \
                                               receiver_id, can_registration.CAN_STR_AUTH_GRANT_MSG, clear_message, self.SSMA_GRANT_MSG_CT_SIZE, stream_id, uid.hex))

        return sending_size

    def _generate_grant_message_sendable(self, receiver_id, sending_size, clear_message, uid):
        ''' this method generates a sendable grant message
            that is encrypted using the ecu key of the 
            target ecu
            
            Input:  receiver_id        string        id of the target ECU
                    sending_size       float         size of the grant message after encryption
                    clear_message      list          content of the grant message
                    uid                uuid          identifier for the message
            Output: seg_message        SegData       sendable encrypted grant message            
        '''
        # extract information
        receiver_key = self.ecu_auth.verified_ecu_keys[receiver_id]
        message_size = sending_size
        
        # encrypt message
        message = encryption_tools.sym_encrypt(clear_message, receiver_key)
        
        # wrap to SegData
        seg_message = SegData(message, message_size)
        seg_message.unique_id = uid 

        return seg_message

    
    def _note_cipher_size_stream_request(self, sender_id, received_message_data, decryption_time):
        ''' this method notes the cipher size for a 
            stream request message that is incoming
            
            Input:    sender_id                string        id of the request message sender ecu
                      received_message_data    SegData       received request message
                      decryption_time          float         decryption time that already passed
            Output:   -
        '''
        
        # extract information
        algorithm = self.ecu_auth.verified_ecu_keys[sender_id].valid_alg
        key_length = self.ecu_auth.verified_ecu_keys[sender_id].valid_key_len
        
        # calculate cipher size
        cipher_size = G().call_or_const(self.SSMA_SIZE_REQ_MSG_CIPHER, self.SSMA_SIZE_REQ_MSG_CONTENT, algorithm, key_length, 'ENCRYPTION') 
         
        # log size
        G().note_sz(str([self.ecu_id, 'SSMA_SIZE_REQ_MSG_CIPHER']), cipher_size);
        L().log(909, self.sim_env.now - decryption_time, self.ecu_id, 'Unknown', 'Unknown', received_message_data.get(), cipher_size)
        
        # monitor 
        monitor_tag = MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE
        msg_id = can_registration.CAN_STR_AUTH_INIT_MSG_STR
        message = received_message_data.get()[1]
        uid = received_message_data.unique_id.hex
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, self.sim_env.now - decryption_time, sender_id, msg_id, message, cipher_size, -1, uid)) 
        

    
    def _distribute_stream(self, dec_message, allowed_receivers, sender_id, stream):
        '''this method distributes the stream that was granted to all receivers
           that are meant for it. This is done by sending a grant message containing
           a symmetric session key to them. This message is encrypted using
           the symmetric ecu key that was previously transmited
           
            Input:    dec_msg            list            decrypted request message
                      allowed_receivers  list            list of all allowed receiver ids
                      sender_id          string          id of this ecu
                      stream             MessageStream   stream object associated to the granted stream
            Output:   success            boolean         true if the stream was transmitted successfully
        '''
        
        # log
        L().log(14, self.ecu_id, stream.receivers, dec_message[1])
        
        # extract information
        session_key, stream_id, nonce = self._get_session_key(stream), dec_message[1], dec_message[2]
        
        # grant only once
        self._expand_already_granted(stream_id, session_key)

        # session key generation
        time_generate_session_key, uid = self._timeout_session_key_generation(stream_id, sender_id)
        yield self.sim_env.timeout(time_generate_session_key)
        
        # send session key
        for receiver_id in allowed_receivers + [sender_id]:
            
            # Create message
            clear_message = self._generate_grant_message(session_key, receiver_id, stream_id, nonce, sender_id)                    
            
            # check receiver key
            if not self._has_receivers_key(receiver_id):  success = False        
                
            else:
                # time to encrypt
                encryption_time = self._timeout_grant_message_encryption(receiver_id)                
                yield self.sim_env.timeout(encryption_time)
                
                # sending size        
                sending_size = self.size_grant_message_encrypted(receiver_id, stream_id, clear_message)                        
                
                # send grant message
                seg_message = self._generate_grant_message_sendable(receiver_id, sending_size, clear_message, uid)
                yield self.sim_env.process(self.comm_mod.send_msg(self.ecu_id, can_registration.CAN_STR_AUTH_GRANT_MSG, seg_message))                 
                success = True
            
            # check success
            if not success and sender_id == receiver_id: success = False
            else: success = True
            
        # return success
        return success
            
    
    def _try_decrypt_stream_request(self, received_message_data, sender_id, decryption_time):
        ''' this method tries to decrypt the request message and returns if it
            was successful or not
            
            Input:  received_message_data    SegData    encrypted stream request message
                    decryption_time          float      time the decryptionn of the stream request takes
           Output:  dec_message              list       clear request message                    
                    decryptable              boolean    true if the message was successfullt decrypted
        '''
        
        # try decrypt
        dec_message = encryption_tools.sym_decrypt(received_message_data.get()[1], self.ecu_auth.verified_ecu_keys[sender_id]) 
        
        # monitor
        monitor_tag = MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE
        cur_time = self.sim_env.now
        msg_id = can_registration.CAN_STR_AUTH_INIT_MSG_STR
        uid = received_message_data.unique_id.hex
        size = self.SSMA_SIZE_REQ_MSG_CONTENT
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, cur_time, sender_id, msg_id, dec_message, size, dec_message[1], uid))

        # successful decryption
        decryptable = True
        if sender_id == None and dec_message != None:
            decryptable = False
        
        # log
        G().note_sz(str([self.ecu_id, 'SSMA_SIZE_REQ_MSG_CONTENT']), self.SSMA_SIZE_REQ_MSG_CONTENT)
        L().log(914, self.sim_env.now, self.ecu_id, dec_message[0], dec_message[1], dec_message, self.SSMA_SIZE_REQ_MSG_CONTENT)
        
        # result
        return dec_message, decryptable
              
                    
    def _extract_stream_request(self, received_message_data, decryption_time):
        ''' this method returns the decrypted stream request message from the
            raw encrypted message. It also states whether the message could be 
            decrypted
            
            Input:  received_message_data    SegData    encrypted stream request message
                    decryption_time          float      time the decryptionn of the stream request takes
            Output: dec_message              list       clear request message
                    sender_id                string     Identifier of the ecu who send the stream request
                    decryptable              boolean    true if the message was successfullt decrypted
        '''
        
        # handle request message        
        sender_id = received_message_data.get()[0]
        self._note_cipher_size_stream_request(sender_id, received_message_data, decryption_time)
        
        # decrypt request message
        dec_message, decryptable = self._try_decrypt_stream_request(received_message_data, sender_id, decryption_time)
        
        # result
        return [dec_message, sender_id, decryptable]

    
    def _get_allowed_stream(self, stream_id, sender_id):
        ''' returns the stream that is allowed for the given
            stream id and sender
            
            Input:    stream_id    integer    id to be checked
                      sender_id    string     sender willing to send this stream
            Output:   receivers    stream     the stream if the sender is allowed to send it
        '''
        
        # allowed streams
        for stream in self.allowed_streams:
            if self._stream_allowed(stream, stream_id, sender_id):
                return stream
        
        # no allowed streams
        L().log(10, self.sim_env.now, self.ecu_id)
        return False
           
    
    def _get_session_key(self, stream):
        ''' Creates a valid session key'''
        session_key = encryption_tools.sym_get_key(self.SSMA_SECM_SES_KEY_ENC_ALG, self.SSMA_SECM_SES_KEY_ENC_KEY_LEN, self.SSMA_SECM_SES_KEY_ENC_ALG_MODE)
        session_key.set_validity(self.sim_env.now + stream.validity)
        stream.valid_till = self.sim_env.now + stream.validity
        return session_key
    
    
    def _timeout_stream_request_decryption(self, received_message):
        ''' this method determines the time that is needed to decrypt the
            received request message.
            
            Input:     received_message    SegData        incoming stream request message
            Output:    decryption_tim      float          time to decrypt the stream request message        
        '''
        
        # log
        L().log(9, self.sim_env.now, self.ecu_id, received_message.get())
        
        # information
        algorithm = self.ecu_auth.verified_ecu_keys[received_message.get()[0]].valid_alg
        algorithm_mode = self.ecu_auth.verified_ecu_keys[received_message.get()[0]].valid_alg_mode
        key_length = self.ecu_auth.verified_ecu_keys[received_message.get()[0]].valid_key_len
        
        # size request message
        cipher_size = G().call_or_const(self.SSMA_SIZE_REQ_MSG_CIPHER, self.SSMA_SIZE_REQ_MSG_CONTENT, algorithm, key_length, 'ENCRYPTION')  
        
        # decryption time        
        decryption_time = time.call(self.SSMA_STREAM_REQ_INI_DECR, algorithm, key_length, cipher_size, algorithm_mode) * self._jitter 
        
        # monitor
        G().to_t(self.sim_env, decryption_time, 'SSMA_STREAM_REQ_INI_DECR', self.__class__.__name__, self.ecu_id)
        
        # return 
        return decryption_time
        
    def _already_granted(self, decrypted_message):
        ''' check if message was granted already if so stop it # remember the allowed streams, 
            send them only anew if they became invalid
        
            Input:     decrypted_message   list        clear stream request message that was received
            Output:    bool                boolean     true if this stream was already granted in this time interval
        '''
        # extract
        stream_id = decrypted_message[1]
        
        # granted already     
        if stream_id in self._already_granted_streams.keys():         
            valid_till = self._already_granted_streams[stream_id]
            
            # request too early
            if self.sim_env.now < valid_till:  
                L().log(17, self.ecu_id, stream_id)
                return True
        return False
        
    
    def _handle_stream_req(self, received_message):
        ''' this method receives a stream request message and handles it by decrypting it first.
            Then this method looks for valid receivers for this stream (stream_id, sender_id) and sends
            the grant message to them if the request message was valid.
            
            Input:     received_message    SegData        incoming stream request message
            Output:     -
        '''
        
        # decryption time
        decryption_time = self._timeout_stream_request_decryption(received_message)        
        yield self.sim_env.timeout(decryption_time)
        
        # decrypted message        
        [decrypted_message, sender_id, decryptable] = self._extract_stream_request(received_message, decryption_time)
        if not decryptable: return G().val_log_info(False, 11)
        else: L().log(12, self.ecu_id)
        
        # check granted already
        if self._already_granted(decrypted_message):
            return
        
        # check timestamp
        if not self._valid_timestamp_and_nonce(decrypted_message[2], decrypted_message[3]): 
            return G().val_log_info(False, 13)
        
        # allowed stream
        stream = self._get_allowed_stream(decrypted_message[1], sender_id)        
        if not stream:
            yield  self.sim_env.process(self._send_deny_msg(decrypted_message, sender_id)); return        
         
        # send grant messages
        res = yield  self.sim_env.process(self._distribute_stream(decrypted_message, stream.receivers, sender_id, stream))
        if not res and res != None: yield  self.sim_env.process(self._send_deny_msg(decrypted_message, sender_id))
    
    
    def _has_receivers_key(self, receiver_id):
        ''' true if the security module has the 
            receivers ecu key
        
            Input:     receiver_id    string     id of the potential receiver
            Output:    bool           boolean    true if this security module has the receivers symmetric key
        '''
        try:
            self.ecu_auth.verified_ecu_keys[receiver_id]
            return True
        except:
            return G().val_log_info(False, 15, receiver_id)
      
    def _clear_deny_message(self, receiver_id, stream_id, nonce):
        ''' returns the clear deny message
            
            Input:    receiver_id    string     id of sender that wants to send
                      stream_id      integer    requested stream id
                      nonce          number     number used once
            Output:   clear_message  list       clear deny message
        
        '''
        # create message
        clear_message = [receiver_id, stream_id, None, nonce]
        
        # log
        L().log(910, self.sim_env.now, self.ecu_id, receiver_id, stream_id, [receiver_id, stream_id, None, nonce], self.SSMA_GRANT_MSG_CT_SIZE); 
      
        return clear_message
    
    @ try_ex
    def _size_encrypted_deny_message(self, receiver_id , stream_id, sender_id, clear_message):
        ''' returns the size of the encrypted deny message
        
            Input:     receiver_id    string     id of receiver that gets this message
                       stream_id      integer    requested stream id
                       sender_id      string     ecu that was requesting the stream
                       clear_message  list       clear deny message 
            Output     message_size   float      size of the encrypted deny message
                       uid            uuid       identifier for this message
        
        '''
        # extract information
        algorithm = self.ecu_auth.verified_ecu_keys[receiver_id].valid_alg
        key_length = self.ecu_auth.verified_ecu_keys[receiver_id].valid_key_len
        
        # determine size
        message_size = G().call_or_const(self.SSMA_SECM_DENY_MSG_SIZE, self.SSMA_GRANT_MSG_CT_SIZE, algorithm, key_length, 'ENCRYPTION')  
        
        # log
        G().note_sz(str([self.ecu_id, 'SSMA_SECM_DENY_MSG_SIZE']), message_size)
        L().log(911, self.sim_env.now, self.ecu_id, receiver_id, stream_id, 'Encrypted Message', message_size)
        
        # Monitor            
        uid = uuid.uuid4()
        monitor_tag = MonitorTags.CP_SEC_ENCRYPTED_DENY_MESSAGE
        msg_id = can_registration.CAN_STR_AUTH_DENY_MSG
        G().mon(self.monitor_lst, MonitorInput([], monitor_tag, self.ecu_id, self.sim_env.now, sender_id, msg_id, clear_message, message_size, stream_id, uid.hex))
        
        # result
        return message_size, uid
    
    
    def _deny_message_sendable(self, receiver_id, clear_message, message_size, uid):
        ''' returns the sendable SegData object for the deny
            message
            
            Input:     receiver_id        string        id of the ECU addressed
                       clear_message      list          clear deny message
                       message_size       integer       size of encrypted deny message
                       uid                uuid          unique id for this message
            Output     seg_message        SegData       sendable deny messages 
        '''
        # encryption
        rec_key = self.ecu_auth.verified_ecu_keys[receiver_id]        
        message = encryption_tools.sym_encrypt(clear_message, rec_key)
        
        # sendable data
        seg_message = SegData(message, message_size)
        seg_message.unique_id = uid       
        
        return seg_message
      
      
    def _send_deny_msg(self, decrypted_message, sender_id):
        ''' if the requested message stream was not granted a deny message
            will be sent to the requesting message sender
            
        '''
        
        # Create: Deny Message: Encrypt with the ECU key  
        receiver_id, stream_id, nonce = decrypted_message[0], decrypted_message[1], decrypted_message[2]  
        
        # encryption time
        time_value, uid = self._timeout_deny_message_encryption(receiver_id, decrypted_message)
        yield self.sim_env.timeout(time_value)     
        
        # clear message
        clear_message = self._clear_deny_message(receiver_id, stream_id, nonce)

        # size message    
        message_size, uid = self._size_encrypted_deny_message(receiver_id, stream_id, sender_id, clear_message)
        
        # sendable message
        seg_message = self._deny_message_sendable(receiver_id, clear_message, message_size, uid)
         
        # send message
        yield self.sim_env.process(self.comm_mod.send_msg(self.ecu_id, can_registration.CAN_STR_AUTH_DENY_MSG, seg_message)) 
    
    
    def set_allowed_streams(self, message_streams_list):
        ''' sets the allowed streams for this security module
            
            Input:     message_streams_list    list    list of allowed message streams
            Output:    -            
        '''        
        self.allowed_streams = message_streams_list        

    
    def _stream_allowed(self, stream, received_message_id, sender_id):
        ''' checks if the current request is allowed 
            
            Input:  stream                MessageStream    requested stream
                    received_message_id   integer          stream id requested
                    sender_id             string           ecu requesting the stream
            Output: bool                  boolean          true if the stream is allowed for this receiver
        '''
        
        #  stream sender ok
        if sender_id != stream.sender_id:
            return False
                
        # request in correct time
        if not (stream.earliest_req <= self.sim_env.now and stream.latest_req >= self.sim_env.now):
            logging.warn("ECU %s: stream %s not allowed. request made in wrong time: %s, expected at latest: %" % \
                         (self.ecu_id, stream.message_id, self.sim_env.now, stream.latest_req))
            return False
        
        # same message id
        if not received_message_id == stream.message_id:
            return False
        
        return True
    
    
    def _verify_nonce(self, nonce):
        ''' this method checks if the given nonce is valid or not
            
            Input:  nonce               integer              number used once                       
            Output: bool                boolean              true if the nonceis valid            
        '''
        # TODO: Implement
        return True

class SimpleTransmitter(object):
    '''
    this class simply transmits messages from the communication module
    '''
    def __init__(self, ecu_id, sim_env):   
        ''' Constructor
            
            Input:  ecu_id                 string                   id of the corresponding AbstractECU
                    sim_env                simpy.Environment        environment of this component
            Output: -            
        '''
        self.sim_env = sim_env  
        self.ecu_id = ecu_id
        self._sync = simpy.Store(self.sim_env, capacity=1)
        self.comm_mod = None
        
    
    def simple_receive(self):
        ''' simply receives messages from the communication module and forwards
            it to the lower layers
            
            Input:     -
            Output:    -
        '''
        [self.msg_id, self.msg_data] = yield self.sim_env.process(self.comm_mod.receive_msg())                          
        self._sync.put(True)
        return [self.msg_id, self.msg_data]
    
