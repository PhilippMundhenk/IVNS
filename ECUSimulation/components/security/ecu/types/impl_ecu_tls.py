from components.base.ecu.software.ecu_software import ECUSoftware
from components.base.ecu.types.impl_ecu_simple import SimpleECU
from components.security.ecu.software.impl_app_layer_secure import SecureApplicationLayer
from config.timing_db_admin import TimingDBMap
from enums.sec_cfg_enum import EnumTrafor, AsymAuthMechEnum, SymAuthMechEnum, \
    AuKeyLengthEnum
from tools.ecu_logging import ECULogger as L, ECULogger
from tools.general import General as G
import math
from math import ceil
import logging
from components.security.ecu.software.impl_comm_module_tls import TLSCommModule
from enums.tls_enums import CompressionMethod
from config import can_registration


class TLSECU(SimpleECU):
    '''
    this ECU enables secure communication using the TLS protocol 
    on the communication layer
    '''
    def __init__(self, sim_env=None, ecu_id=None, data_rate=None, size_sending_buffer=None, size_receive_buffer=None):
        ''' Constructor
        
            Input:  sim_env                simpy.Environment        environment in which this ECU lives
                    ecu_id                 string                   id of this ECU component 
                    data_rate              integer                  data_rate of the connected bus
                    size_sending_buffer    float                    size of the sending buffer of this ECU
                    size_receive_buffer    float                    size of the receiving buffer of this ECU   
            Output: -
        '''   
        
        # set settings
        self.set_settings()
        self._authenticated = False
        self._allowed_streams = can_registration.TLS_MESSAGES
        
        # no instantiation
        if sim_env == None: return  
        
        # set SW and HW
        SimpleECU.__init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer)                
        self.ecuSW = ECUSoftware(sim_env, TLSCommModule(sim_env, ecu_id), SecureApplicationLayer(sim_env, ecu_id))
        
        # connect
        self._connect_hw_sw()                
       
     
    def add_sending(self, start_time, interval, message_id, data, data_len):
        ''' this method adds a new sending action to the application layer of this 
            ECU. Then the message will start sending messages in the defined interval
            starting at the specified start_time
            
            Input:  start_time    float            time at which the first message is sent
                    interval      float            period within which the messages are sent
                    message_id    integer          message identifier of the messages that are sent
                    data          object/..        content of the messages that are sent
                    data_length   float            size of one message
            Output: -        
        '''
        self.ecuSW.app_lay.add_sending(start_time, interval, message_id, data, data_len)
        
    
    def get_type_id(self):
        ''' returns the id of this ECU type
        
            Input:    -
            Output:   ecu_type    string    type of this ECU; e.g.'TLSECU'
        '''
        return "TLSECU"
    
    
    def add_stream(self, new_stream):
        ''' this method adds a new stream that is allowed to the TESLA environment.
            This stream will then be legal and the ECUs will send according to those
            streams.
            
            Input:    new_stream    MessageStream    message stream that is added to the environment
            Output:   -
        '''
        # push to communication module
        self.ecuSW.comm_mod.add_stream(new_stream)

        # add HW filter
        if self.ecu_id in new_stream.receivers and \
           new_stream.message_id not in self._allowed_streams:
            self._allowed_streams += [new_stream.message_id]
            self.ecuHW.transceiver.install_filter(self._allowed_streams)
    
    def set_max_message_number(self, nr_messages):
        ''' sets the number of messages that are sent by this ecu per
            stream
        
            Input:    nr_messages    int    number of messages sent
            Output:    -
        '''
        self.ecuSW.app_lay.set_max_message_number(nr_messages)
    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        #=======================================================================
        #     General Settings
        #=======================================================================    
        self.settings['p_tls_record_protocol_version'] = 'ecuSW.comm_mod._record.TLSRL_PROTOCOL_VERSION'  # Protocol Version
        
        # Compression
        self.settings['p_tls_record_compress_algorithm'] = 'ecuSW.comm_mod._record.TLSR_COMPRESSION_ALGORITHM'  # Compression Algorithm used in Record Layer
        
        # MAC Creation
        self.settings['p_tls_record_mac_algorithm'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_MAC_ALGORITHM'  # MAC Algorithm used in Record Layer
        self.settings['p_tls_record_mac_key_len'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_MAC_KEY_LEN'  # MAC Keylength used in Record Layer
         
        # Encryption
        self.settings['p_tls_record_enc_algorithm'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_ENC_ALGORITHM'  # Encryption Algorithm used in Record Layer
        self.settings['p_tls_record_enc_key_len'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_ENC_KEY_LEN'  # Keylength of ALgorithm used in Record Layer
        self.settings['p_tls_record_enc_algorithm_mode'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE'  # Mode of algorithm used in Record Layer
         
        # Server Certificate 
        self.settings['p_tls_hand_server_cert_enc_algorithm'] = 'ecuSW.comm_mod._record.TLSH_SERV_CERT_ENC_ALG'  # Encryption Algorithm used in Server Certificate
        self.settings['p_tls_hand_server_cert_enc_key_len'] = 'ecuSW.comm_mod._record.TLSH_SERV_CERT_ENC_KEY_LEN'  # Keylength for Encryption Algorithm used in Server Certificate  
        self.settings['p_tls_hand_server_cert_enc_algorithm_option'] = 'ecuSW.comm_mod._record.TLSH_SERV_CERT_ENC_ALG_OPTION'  # Option for Encryption Algorithm used in Server Certificate
        self.settings['p_tls_hand_server_cert_hash_mech'] = 'ecuSW.comm_mod._record.TLSH_SERV_CERT_HASH_MECH'  # Hash algorithm used in the Server Certificate
        self.settings['p_tls_hand_server_cert_ca_len'] = 'ecuSW.comm_mod._record.TLSH_SERV_CERT_CA_LEN'  
         
        # PRF Algorithm
        self.settings['p_tls_hand_prf_master_generation'] = 'ecuSW.comm_mod._record.TLSH_PRF_MASTER_SEC_GENERATION'  # PRF Algorithm used to create the master secret
        
        # Client certificate 
        self.settings['p_tls_hand_client_cert_enc_algorithm'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_CERT_ENC_ALG'  
        self.settings['p_tls_hand_client_cert_enc_key_len'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_CERT_ENC_KEY_LEN'  
        self.settings['p_tls_hand_client_cert_enc_algorithm_option'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_CERT_ENC_ALG_OPTION'  
         
        # Finished message algorithms
        self.settings['p_tls_hand_finish_hash_algorithm'] = 'ecuSW.comm_mod._record.TLSH_FINISH_MESSAGE_HASH_ALGORITHM'  # Hash algorithm used to create the verification hash in the client/server finished message
        
        self.settings['p_tls_hand_server_finish_rec_prf_algorithm'] = 'ecuSW.comm_mod._record.TLSH_SERVER_REC_FINISHED_PRF_ALG'  # PRF algorithm used to create the verification hash in the server finished message on receiving side
        self.settings['p_tls_hand_server_finish_send_prf_algorithm'] = 'ecuSW.comm_mod._record.TLSH_SERVER_SEND_FINISHED_PRF_ALG'  # PRF algorithm used to create the verification hash in the server finished message on sending side
        
        self.settings['p_tls_hand_client_finish_send_prf_algorithm'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_SEND_FINISHED_PRF_ALG'  # PRF algorithm used to create the verification hash in the client finished message on sending side
        self.settings['p_tls_hand_client_finish_rec_prf_algorithm'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_REC_FINISHED_PRF_ALG'  # PRF algorithm used to create the verification hash in the client finished message on receiving side
        
        #=======================================================================
        #     Sizes
        #=======================================================================    
        # Record Layer 
        self.settings['p_tls_record_compressed_size'] = 'ecuSW.comm_mod._record.TLSR_COMPRESSED_SIZE'  # Size of message after being compressed used in Record Layer                
        self.settings['p_tls_record_mac_inputsize'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_MAC_INPUT_SIZE'  # Input Size for the mac algorithm used in Record Layer at sending side
        self.settings['p_tls_record_mac_outputsize'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_MAC_SIZE'  # Output size of the mac algorithm used in Record Layer at sending side        
        self.settings['p_tls_record_enc_size'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_ENC_SIZE'  # Size of message after being encrypted in the record layer
        self.settings['p_tls_record_dec_mac_inputsize'] = 'ecuSW.comm_mod._record.TLSR_DEC_BLOCKCIPHER_MAC_INPUT_SIZE'  # Input Size for the mac algorithm used in Record Layer at receiving side
        self.settings['p_tls_record_dec_mac_outputsize'] = 'ecuSW.comm_mod._record.TLSR_DEC_BLOCKCIPHER_MAC_SIZE'  # Output size of the mac algorithm used in Record Layer at receiving side
        
        # Handshake        
        self.settings['p_tls_hand_cert_verify_cipher_size'] = 'ecuSW.comm_mod._record.TLSH_CERT_VERIFY_CIPHER_SIZE'  # Size of certificate Verify message after encryption
        self.settings['p_tls_hand_cert_verify_clear_size'] = 'ecuSW.comm_mod._record.TLSH_CERT_VERIFY_CLEAR_SIZE'  # Size of certificate Verify message before encryption        
        
        self.settings['p_tls_hand_server_cert_unsigned_size'] = 'ecuSW.comm_mod._record.TLSH_SERV_CERT_UNSIGNED_SIZE'  # Size of the Server Certificate before Sign process
        self.settings['p_tls_hand_server_cert_signed_size'] = 'ecuSW.comm_mod._record.TLSH_SERV_CERT_SIGNED_SIZE'  # Size of the Signed Hash in the Server Certificate        
        
        self.settings['p_tls_hand_client_keyex_cipher_size'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_KEYEX_CIPHER_SIZE'  # Size of the client key exchange message after being encrypted     
        self.settings['p_tls_hand_client_keyex_clear_size'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_KEYEX_CLEAR_SIZE'  # Size of the client key exchange message before being encrypted                
        
        self.settings['p_tls_hand_server_finish_rec_hash_size'] = 'ecuSW.comm_mod._record.TLSH_SERVER_REC_FINISHED_HASH_SIZE'  # Size of the server finished message hash on the receiving side
        self.settings['p_tls_hand_server_finish_rec_content_size'] = 'ecuSW.comm_mod._record.TLSH_SERVER_REC_FINISHED_CONTENT_SIZE'  # Size of the server finished message content on the receiving side        
        self.settings['p_tls_hand_client_finish_rec_hash_size'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_REC_FINISHED_HASH_SIZE'  # Size of the client finished message hash on the receiving side
        self.settings['p_tls_hand_client_finish_rec_content_size'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_REC_FINISHED_CONTENT_SIZE'  # Size of the client finished message content on the receiving side
        self.settings['p_tls_hand_server_finish_send_hash_size'] = 'ecuSW.comm_mod._record.TLSH_SERVER_SEND_FINISHED_HASH_SIZE'  # Size of the server finished message hash on the sending side
        self.settings['p_tls_hand_server_finish_send_content_size'] = 'ecuSW.comm_mod._record.TLSH_SERVER_SEND_FINISHED_CONTENT_SIZE'  # Size of the server finished message content on the sending side        
        self.settings['p_tls_hand_client_finish_send_hash_size'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_SEND_FINISHED_HASH_SIZE'  # Size of the client finished message hash on the sending side
        self.settings['p_tls_hand_client_finish_send_content_size'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_SEND_FINISHED_CONTENT_SIZE'  # Size of the client finished message content on the sending side        
        
        self.settings['p_tls_hand_client_cert_unsigned_size'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_CERT_UNSIGNED_SIZE'  # Size of certificate unsigned
        
        self.settings['p_tls_certificate_send_size'] = 'ecuSW.comm_mod._record.TLSH_CERT_SEND_SIZE'  # Size of one certificate (root certificate)
        
        # Sending size
        self.settings['p_tls_hand_client_hello_size'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_HELLO_SEND_SIZE'  
        self.settings['p_tls_hand_cert_request_send_size'] = 'ecuSW.comm_mod._record.TLSH_CERT_REQUEST_SEND_SIZE'  # Sending size of a certificate request message         
        self.settings['p_tls_hand_server_hello_send_size'] = 'ecuSW.comm_mod._record.TLSH_SERVER_HELLO_SEND_SIZE'  # Sending size of server hello message 
        self.settings['p_tls_hand_server_hello_done_send_size'] = 'ecuSW.comm_mod._record.TLSH_SERVER_HELLO_DONE_SEND_SIZE'  # Sending size of a server hello done message 
        
        #=======================================================================
        #     Timings
        #=======================================================================
        # Record Layer
        self.settings['t_tls_record_compression'] = 'ecuSW.comm_mod._record.TLSR_COMPRESSION_TIME'  
        self.settings['t_tls_record_decompression'] = 'ecuSW.comm_mod._record.TLSR_DECOMPRESSION_TIME'  
        self.settings['t_tls_record_mac_send_side'] = 'ecuSW.comm_mod._record.TLSR_MAC_BLOCKCIPHER_SEND_TIME'  # time to create MAC on sending side of record layer
        self.settings['t_tls_record_mac_rec_side'] = 'ecuSW.comm_mod._record.TLSR_MAC_BLOCKCIPHER_REC_TIME'  # time to create MAC on receiving side of record layer
        self.settings['t_tls_record_enc'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_ENC_TIME'  # time to encrypt the block cipher in the record layer        
        self.settings['t_tls_record_dec'] = 'ecuSW.comm_mod._record.TLSR_BLOCKCIPHER_DEC_TIME'  # time to encrypt the block cipher in the record layer       
        
        # Handshake
        self.settings['t_tls_hand_enc_client_keyex_msg'] = 'ecuSW.comm_mod._record.TLSH_ENC_CLIENT_KEYEX_TIME'  # Time to encrypt the client keyexchange
        self.settings['t_tls_hand_dec_client_keyex_msg'] = 'ecuSW.comm_mod._record.TLSH_DEC_CLIENT_KEYEX_TIME'  # Time to decrypt the client keyexchange
        self.settings['t_tls_hand_dec_cert_verify_msg'] = 'ecuSW.comm_mod._record.TLSH_DEC_CERT_VERIFY_TIME'  # Time to decrypt the certificate verify message
        self.settings['t_tls_hand_enc_cert_verify_msg'] = 'ecuSW.comm_mod._record.TLSH_ENC_CERT_VERIFY_TIME'  # Time to encrypt the certificate verify message
        self.settings['t_tls_hand_prf'] = 'ecuSW.comm_mod._record.TLSH_PRF_WORKING_TIME'  # Time the PRF Algorithm needs
        self.settings['t_tls_hand_rec_server_finish_hash'] = 'ecuSW.comm_mod._record.TLSH_SERVER_REC_FINISHED_HASH_TIME'  # time to hash the server finished message on receiver side
        self.settings['t_tls_hand_rec_client_finish_hash'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_REC_FINISHED_HASH_TIME'  # time to hash the server finished message on receiver side
        self.settings['t_tls_hand_server_hello_done_verify_cert'] = 'ecuSW.comm_mod._record.TLSH_SERV_HELLO_DONE_VERIFY_CERT_TIME'  
        self.settings['t_tls_hand_send_server_finish_hash'] = 'ecuSW.comm_mod._record.TLSH_SERVER_SEND_FINISHED_HASH_TIME'  # time to hash the client finished message on sending side
        self.settings['t_tls_hand_send_client_finish_hash'] = 'ecuSW.comm_mod._record.TLSH_CLIENT_SEND_FINISHED_HASH_TIME'  # time to hash the client finished message on sending side
        self.settings['t_tls_hand_verify_client_cert'] = 'ecuSW.comm_mod._record.TLSH_CERIFY_CLIENT_CERT_TIME'
             
        return self.settings
        
    
    def monitor_update(self):
        ''' returns a list of monitor inputs
            
            Input:    -
            Output:   list    list    list of MonitorInput objects
        '''
        return self.ecuSW.comm_mod.monitor_update()

class StdTLSECUTimingFunctions(object):
    ''' If used this class defines the timing behaviour
        
        Looks up values in the measurements.db
        if no value is found tries to interpolate it from neighbours
    '''

    def __init__(self, main_library_tag='CyaSSL'):
        ''' Constructor
            
            Input:  main_library_tag    string  tag of the library that will be used for     
                                                access of the timing values per default
            Output: -
        '''
        self.available_tags = ['CyaSSL', 'Crypto_Lib_HW', 'Crypto_Lib_SW']

        self.library_tag = main_library_tag  # e.g. CyaSSL, or CryptoLib

        self.function_map = {}
            
        # Record Layer
        self.function_map['t_tls_record_compression'] = self.c_t_tls_record_compression
        self.function_map['t_tls_record_decompression'] = self.c_t_tls_record_decompression
        self.function_map['t_tls_record_mac_send_side'] = self.c_t_tls_record_mac_send_side
        self.function_map['t_tls_record_mac_rec_side'] = self.c_t_tls_record_mac_rec_side
        self.function_map['t_tls_record_enc'] = self.c_t_tls_record_enc    
        self.function_map['t_tls_record_dec'] = self.c_t_tls_record_dec
        
        # Handshake
        self.function_map['t_tls_hand_enc_client_keyex_msg'] = self.c_t_tls_hand_enc_client_keyex_msg
        self.function_map['t_tls_hand_dec_client_keyex_msg'] = self.c_t_tls_hand_dec_client_keyex_msg
        self.function_map['t_tls_hand_dec_cert_verify_msg'] = self.c_t_tls_hand_dec_cert_verify_msg
        self.function_map['t_tls_hand_enc_cert_verify_msg'] = self.c_t_tls_hand_enc_cert_verify_msg
        self.function_map['t_tls_hand_prf'] = self.c_t_tls_hand_prf
        self.function_map['t_tls_hand_rec_server_finish_hash'] = self.c_t_tls_hand_rec_server_finish_hash
        self.function_map['t_tls_hand_rec_client_finish_hash'] = self.c_t_tls_hand_rec_client_finish_hash
        self.function_map['t_tls_hand_server_hello_done_verify_cert'] = self.c_t_tls_hand_server_hello_done_verify_cert
        self.function_map['t_tls_hand_send_server_finish_hash'] = self.c_t_tls_hand_send_server_finish_hash
        self.function_map['t_tls_hand_send_client_finish_hash'] = self.c_t_tls_hand_send_client_finish_hash
        self.function_map['t_tls_hand_verify_client_cert'] = self.c_t_tls_hand_verify_client_cert
             
        # Record Layer
        self.library_tags = {}
        self.library_tags['t_tls_record_compression'] = self.library_tag
        self.library_tags['t_tls_record_decompression'] = self.library_tag
        self.library_tags['t_tls_record_mac_send_side'] = self.library_tag
        self.library_tags['t_tls_record_mac_rec_side'] = self.library_tag
        self.library_tags['t_tls_record_enc'] = self.library_tag    
        self.library_tags['t_tls_record_dec'] = self.library_tag
        
        # Handshake
        self.library_tags['t_tls_hand_enc_client_keyex_msg'] = self.library_tag
        self.library_tags['t_tls_hand_dec_client_keyex_msg'] = self.library_tag
        self.library_tags['t_tls_hand_dec_cert_verify_msg'] = self.library_tag
        self.library_tags['t_tls_hand_enc_cert_verify_msg'] = self.library_tag
        self.library_tags['t_tls_hand_prf'] = self.library_tag
        self.library_tags['t_tls_hand_rec_server_finish_hash'] = self.library_tag
        self.library_tags['t_tls_hand_rec_client_finish_hash'] = self.library_tag
        self.library_tags['t_tls_hand_server_hello_done_verify_cert'] = self.library_tag
        self.library_tags['t_tls_hand_send_server_finish_hash'] = self.library_tag
        self.library_tags['t_tls_hand_send_client_finish_hash'] = self.library_tag
        self.library_tags['t_tls_hand_verify_client_cert'] = self.library_tag
         
    
    
    def get_function_map(self):
        ''' returns the function_map that maps the timing parameters to 
            functions that are called when the timing parameters are accessed
            
            
            Input:    -
            Output:   function_map    dictionary        maps timing parameters to functions. 
                                                        Key:     settings identifier
                                                        Value:   method called for this setting 
        '''
        return self.function_map

    
    def c_t_tls_record_compression(self, msg_size, compr_alg):
        ''' depends on compression algorithm: here none used'''
        if compr_alg == CompressionMethod.NULL:
            return 0        
        return 0
    
    
    def c_t_tls_record_decompression(self, compressed_msg_size, compr_alg):
        ''' depends on compression algorithm: here none used'''
        if compr_alg == CompressionMethod.NULL:
            return 0     
        return 0
    
    
    def c_t_tls_record_mac_send_side(self, msg_size, mac_alg, mac_key_len):
        ''' use AES CMAC for creation'''
        # Create sending hash
        try:
            # extract infos
            L().log(605, mac_alg, msg_size)
            algorithm = EnumTrafor().to_value(mac_alg)
            key_len = EnumTrafor().to_value(mac_key_len)
            alg_mode = "CMAC"
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(alg_mode=alg_mode, lib=self.library_tags['t_tls_record_mac_send_side'], keylen=key_len, mode='ENCRYPTION', alg=algorithm, data_size=msg_size, description='t_tls_record_mac_send_side')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_tls_record_mac_send_side')
            return 0.01  # self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_record_mac_send_side'")
            return 0.000000001
    
    
    def c_t_tls_record_mac_rec_side(self, mac_size, mac_alg, mac_key_len):
        # Create verification hash
        try:
            # extract infos
            L().log(605, mac_alg, mac_size)
            algorithm = EnumTrafor().to_value(mac_alg)
            key_len = EnumTrafor().to_value(mac_key_len)
            alg_mode = "CMAC"
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(alg_mode=alg_mode, lib=self.library_tags['t_tls_record_mac_rec_side'], keylen=key_len, mode='ENCRYPTION', alg=algorithm, data_size=mac_size, description='t_tls_record_mac_rec_side')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_tls_record_mac_rec_side')
            return 0.01  # self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_record_mac_rec_side'")
            return 0.000000001
        return 0
    
    
    def c_t_tls_record_enc(self, msg_size, enc_alg, enc_key_len, enc_alg_mode):
        # Encrypt the content with symmetric algorithm
        try:
            # extract infos
            algorithm = EnumTrafor().to_value(enc_alg)
            algorithm_mode = EnumTrafor().to_value(enc_alg_mode)
            key_len = EnumTrafor().to_value(enc_key_len) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_record_enc'], alg_mode=algorithm_mode, mode='ENCRYPTION', keylen=key_len, alg=algorithm, data_size=msg_size, description='t_tls_record_enc')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_tls_record_enc')        
            return 0.01  
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_record_enc'")
            return 0.000000001 
    
    def c_t_tls_record_dec(self, msg_size, enc_alg, enc_key_len, enc_alg_mode):
        # Decrypt the content with symmetric algorithm
        try:
            # extract infos
            algorithm = EnumTrafor().to_value(enc_alg)
            algorithm_mode = EnumTrafor().to_value(enc_alg_mode)
            key_len = EnumTrafor().to_value(enc_key_len) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_record_dec'], alg_mode=algorithm_mode, mode='DECRYPTION', keylen=key_len, alg=algorithm, data_size=msg_size, description='t_tls_record_dec')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_tls_record_dec')        
            return 0.01  
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_record_dec'")
            return 0.000000001 
    
    def c_t_tls_hand_dec_cert_verify_msg(self, dec_alg, dec_key_len, msg_size, alg_option):
        # Private decryption
        try:
            # extract information
            L().log(604, dec_alg, dec_key_len, msg_size)
            algorithm = EnumTrafor().to_value(dec_alg)
            key_len = EnumTrafor().to_value(dec_key_len)
            
            # read Database
            if dec_alg == AsymAuthMechEnum.ECC: 
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_dec_cert_verify_msg'], mode='DECRYPTION', param_len=key_len, alg=algorithm, data_size=msg_size, description='t_tls_hand_dec_cert_verify_msg')
                
            else: 
                # RSA: have to slice the message and encrypt each of those
                if msg_size > ((float(key_len) / 8) - 11): size_to_enc_in = ceil((float(key_len) / 8) - 11)
                else: size_to_enc_in = msg_size
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_dec_cert_verify_msg'], exp=alg_option, mode='DECRYPTION', keylen=key_len, \
                                                       alg=algorithm, data_size=size_to_enc_in, description='t_tls_hand_dec_cert_verify_msg')
                
                # RSA: have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(msg_size / ((float(key_len) / 8) - 11))
                db_val = db_val * nr_chuncks
                
            # return result
            if db_val: return G().val_log_info(db_val, 602, db_val)        
            else:  L().log(603, 't_tls_hand_dec_cert_verify_msg')
        
            return 0.001  
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_hand_dec_cert_verify_msg'")
            return 0.000000001
        
    
    def c_t_tls_hand_enc_cert_verify_msg(self, enc_alg, enc_key_len, msg_size, alg_option):
        # Public encrypt
        try:
            # extract information
            L().log(604, enc_alg, enc_key_len, msg_size)
            algorithm = EnumTrafor().to_value(enc_alg)
            key_len = EnumTrafor().to_value(enc_key_len)
            
            # read Database
            if enc_alg == AsymAuthMechEnum.ECC: 
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_enc_cert_verify_msg'], mode='ENCRYPTION', param_len=key_len, alg=algorithm, \
                                                        data_size=msg_size, description='t_tls_hand_enc_cert_verify_msg')
                
            else: 
                # RSA: have to slice the message and encrypt each of those
                if msg_size > ((float(key_len) / 8) - 11): size_to_enc_in = ceil((float(key_len) / 8) - 11)
                else: size_to_enc_in = msg_size
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_enc_cert_verify_msg'], exp=alg_option, mode='ENCRYPTION', keylen=key_len, \
                                                       alg=algorithm, data_size=size_to_enc_in, description='t_tls_hand_enc_cert_verify_msg')
                
                # RSA: have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(msg_size / ((float(key_len) / 8) - 11))
                db_val = db_val * nr_chuncks
                
            # return result
            if db_val: return G().val_log_info(db_val, 602, db_val)        
            else:  L().log(603, 't_tls_hand_enc_cert_verify_msg')
        
            return 0.001  
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_hand_enc_cert_verify_msg'")
            return 0.000000001
    
    
    def c_t_tls_hand_prf(self, input_size, prf_enum):
        ''' key generation with AES is a Random Function so same as a PRF'''
        try:
            # extract information
            algorithm = EnumTrafor().to_value(SymAuthMechEnum.AES)
            key_len = EnumTrafor().to_value(AuKeyLengthEnum.bit_192)
            
            # read Database
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_prf'], mode='KEYGEN', keylen=key_len, alg=algorithm, description='t_tls_hand_prf')
            
            # return result
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                L().log(603, 't_tls_hand_prf')
        
            return 0.001
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_hand_prf'")
            return 0.000000001 

    
    def c_t_tls_hand_rec_server_finish_hash(self, input_size, hash_alg):
        try:
            # extract infos
            L().log(605, hash_alg, input_size)
            algorithm = EnumTrafor().to_value(hash_alg)
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_record_mac_rec_side'], mode='HASH', alg=algorithm, data_size=input_size, description='t_tls_record_mac_rec_side')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_tls_record_mac_rec_side')
            return 0.01  # self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_record_mac_rec_side'")
            return 0.000000001
        return 0
    
    
    def c_t_tls_hand_rec_client_finish_hash(self, input_size, hash_alg):
        try:
            # extract infos
            L().log(605, hash_alg, input_size)
            algorithm = EnumTrafor().to_value(hash_alg)
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_record_mac_rec_side'], mode='HASH', alg=algorithm, data_size=input_size, description='t_tls_record_mac_rec_side')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_tls_record_mac_rec_side')
            return 0.01  # self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_record_mac_rec_side'")
            return 0.000000001
        return 0    
    
    
    def c_t_tls_hand_verify_client_cert(self, cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn, cert_size):
        ''' time to validate the certificate'''
        try:
            # extract parameters
            db_value = False
            algorithm = EnumTrafor().to_value(cert_enc_mech)
            hash_algorithm = EnumTrafor().to_value(cert_hash_mech)
            key_length = EnumTrafor().to_value(cert_enc_keylen)        
            
            # logging
            L().log(601, cert_enc_mech, cert_enc_keylen, cert_size_hashtosign, cert_ca_len)            
        
            # CrypLi RSA: Verify = Time of hash creation + time to encrypt hash / CyaSSL & CrypLi ECC: Verify operation
            if cert_enc_mech == AsymAuthMechEnum.ECC:  
                db_value = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_verify_client_cert'], mode='VERIFY', param_len=key_length, alg=algorithm, data_size=cert_size_hashtosign, description='t_tls_hand_verify_client_cert')                
            
            if self.library_tags['t_tls_hand_verify_client_cert'] in ["Crypto_Lib_SW", "Crypto_Lib_HW"] and cert_enc_mech == AsymAuthMechEnum.RSA:  
                # 1. create hash of certificate content
                db_val_1 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_verify_client_cert'], mode='HASH', alg=hash_algorithm, data_size=cert_size, description='t_tls_hand_verify_client_cert')
                
                # 2. decrypt digital signature (signed hash size) using public key of certificate (public key operation -> similar to public encrypt)
                if cert_size_hashsigned > ((key_length / 8) - 11): 
                    cert_size_hashsigned_in = ceil((float(key_length) / 8) - 11)
                else:
                    cert_size_hashsigned_in = cert_size_hashsigned
                db_val_2 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_verify_client_cert'], mode='VERIFY', keylen=key_length, alg=algorithm, data_size=cert_size_hashsigned_in, exp=cert_alg_optn, description='t_tls_hand_verify_client_cert')     
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(cert_size_hashsigned / ((float(key_length) / 8) - 11))
                db_val_2 = db_val_2 * nr_chuncks
                
                # 3. create hash of digital signature                 
                db_val_3 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_verify_client_cert'], mode='HASH', alg=hash_algorithm, data_size=cert_size_hashtosign, description='t_tls_hand_verify_client_cert')
                
                
                db_value = db_val_1 + db_val_2 + db_val_3
    
            if self.library_tags['t_tls_hand_verify_client_cert'] == "CyaSSL" and cert_enc_mech == AsymAuthMechEnum.RSA:  
                # 1. create hash of certificate content
                db_val_1 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_verify_client_cert'], mode='HASH', alg=hash_algorithm, data_size=cert_size, description='t_tls_hand_verify_client_cert')
                
                # 2. decrypt digital signature (signed hash size) using public key of certificate (public key operation -> similar to public encrypt)
                if cert_size_hashsigned > ((key_length / 8) - 11): 
                    cert_size_hashsigned_in = ceil((float(key_length) / 8) - 11)
                else:
                    cert_size_hashsigned_in = cert_size_hashsigned
                db_val_2 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_verify_client_cert'], mode='ENCRYPTION', keylen=key_length, alg=algorithm, data_size=cert_size_hashsigned_in, exp=cert_alg_optn, description='t_tls_hand_verify_client_cert')     
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(cert_size_hashsigned / ((float(key_length) / 8) - 11))
                db_val_2 = db_val_2 * nr_chuncks
                
                # 3. create hash of digital signature                 
                db_val_3 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_verify_client_cert'], mode='HASH', alg=hash_algorithm, data_size=cert_size_hashtosign, description='t_tls_hand_verify_client_cert')
                
                
                db_value = db_val_1 + db_val_2 + db_val_3
    
            # Set value
            if db_value: 
                L().log(602, db_value)           
            else:
                logging.warn("Error: Could not find in DB the Value in 't_tls_hand_verify_client_cert' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_tls_hand_verify_client_cert'], cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn]))
                return G().val_log_info(0.0000000001 , 603, 't_tls_hand_verify_client_cert')
    
            # repeat cert_ca_len times
            abs_time = cert_ca_len * db_value
            
            return abs_time  # self.settings['t_tls_hand_verify_client_cert'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ADV_SEC_MOD_CERT_VAL'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_tls_hand_verify_client_cert' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_tls_hand_verify_client_cert'], cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn]))
            return 0.000000001
    
    
    def c_t_tls_hand_server_hello_done_verify_cert(self, cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn, cert_size):
        ''' time to validate the certificate'''
        try:
            # extract parameters
            db_value = False
            algorithm = EnumTrafor().to_value(cert_enc_mech)
            hash_algorithm = EnumTrafor().to_value(cert_hash_mech)
            key_length = EnumTrafor().to_value(cert_enc_keylen)        
            
            # logging
            L().log(601, cert_enc_mech, cert_enc_keylen, cert_size_hashtosign, cert_ca_len)            
        
            # CrypLi RSA: Verify = Time of hash creation + time to encrypt hash / CyaSSL & CrypLi ECC: Verify operation
            if cert_enc_mech == AsymAuthMechEnum.ECC:  
                db_value = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_server_hello_done_verify_cert'], mode='VERIFY', param_len=key_length, alg=algorithm, data_size=cert_size_hashtosign, description='t_tls_hand_server_hello_done_verify_cert')                
            
            if self.library_tags['t_tls_hand_server_hello_done_verify_cert'] in ["Crypto_Lib_SW", "Crypto_Lib_HW"] and cert_enc_mech == AsymAuthMechEnum.RSA:  
                # 1. create hash of certificate content
                db_val_1 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_server_hello_done_verify_cert'], mode='HASH', alg=hash_algorithm, data_size=cert_size, description='t_tls_hand_server_hello_done_verify_cert')
                
                # 2. decrypt digital signature (signed hash size) using public key of certificate (public key operation -> similar to public encrypt)
                if cert_size_hashsigned > ((key_length / 8) - 11): 
                    cert_size_hashsigned_in = ceil((float(key_length) / 8) - 11)
                else:
                    cert_size_hashsigned_in = cert_size_hashsigned
                db_val_2 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_server_hello_done_verify_cert'], mode='VERIFY', keylen=key_length, alg=algorithm, data_size=cert_size_hashsigned_in, exp=cert_alg_optn, description='t_tls_hand_server_hello_done_verify_cert')     
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(cert_size_hashsigned / ((float(key_length) / 8) - 11))
                db_val_2 = db_val_2 * nr_chuncks
                
                # 3. create hash of digital signature                 
                db_val_3 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_server_hello_done_verify_cert'], mode='HASH', alg=hash_algorithm, data_size=cert_size_hashtosign, description='t_tls_hand_server_hello_done_verify_cert')
                
                
                db_value = db_val_1 + db_val_2 + db_val_3
            if self.library_tags['t_tls_hand_server_hello_done_verify_cert'] == "CyaSSL" and cert_enc_mech == AsymAuthMechEnum.RSA:  
                # 1. create hash of certificate content
                db_val_1 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_server_hello_done_verify_cert'], mode='HASH', alg=hash_algorithm, data_size=cert_size, description='t_tls_hand_server_hello_done_verify_cert')
                
                # 2. decrypt digital signature (signed hash size) using public key of certificate (public key operation -> similar to public encrypt)
                if cert_size_hashsigned > ((key_length / 8) - 11): 
                    cert_size_hashsigned_in = ceil((float(key_length) / 8) - 11)
                else:
                    cert_size_hashsigned_in = cert_size_hashsigned
                db_val_2 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_server_hello_done_verify_cert'], mode='ENCRYPTION', keylen=key_length, alg=algorithm, data_size=cert_size_hashsigned_in, exp=cert_alg_optn, description='t_tls_hand_server_hello_done_verify_cert')     
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(cert_size_hashsigned / ((float(key_length) / 8) - 11))
                db_val_2 = db_val_2 * nr_chuncks
                
                # 3. create hash of digital signature                 
                db_val_3 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_server_hello_done_verify_cert'], mode='HASH', alg=hash_algorithm, data_size=cert_size_hashtosign, description='t_tls_hand_server_hello_done_verify_cert')
                
                
                db_value = db_val_1 + db_val_2 + db_val_3
    
            # Set value
            if db_value: 
                L().log(602, db_value)           
            else:
                logging.warn("Error: Could not find in DB the Value in 't_tls_hand_server_hello_done_verify_cert' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_tls_hand_server_hello_done_verify_cert'], cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn]))
                return G().val_log_info(0.0000000001 , 603, 't_tls_hand_server_hello_done_verify_cert')
    
            # repeat cert_ca_len times
            abs_time = cert_ca_len * db_value
            
            return abs_time  # self.settings['t_tls_hand_server_hello_done_verify_cert'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ADV_SEC_MOD_CERT_VAL'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_tls_hand_server_hello_done_verify_cert' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_tls_hand_server_hello_done_verify_cert'], cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn]))
            return 0.000000001
        
    
    def c_t_tls_hand_send_server_finish_hash(self, input_size, hash_alg):
        try:
            # extract infos
            L().log(605, hash_alg, input_size)
            algorithm = EnumTrafor().to_value(hash_alg)
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_send_server_finish_hash'], mode='HASH', alg=algorithm, data_size=input_size, description='t_tls_hand_send_server_finish_hash')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_tls_hand_send_server_finish_hash')
            return 0.01  # self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_hand_send_server_finish_hash'")
            return 0.000000001
        return 0
    
    
    def c_t_tls_hand_send_client_finish_hash(self, input_size, hash_alg):
        try:
            # extract infos
            L().log(605, hash_alg, input_size)
            algorithm = EnumTrafor().to_value(hash_alg)
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_send_client_finish_hash'], mode='HASH', alg=algorithm, data_size=input_size, description='t_tls_hand_send_client_finish_hash')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_tls_hand_send_client_finish_hash')
            return 0.01  # self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        except:
            logging.error("Error: Could not calculate the Value in 't_tls_record_mac_rec_side'")
            return 0.000000001
        return 0
    
    
    def c_t_tls_hand_enc_client_keyex_msg(self, pub_enc_alg, pub_enc_keylen, size_to_enc, pub_enc_alg_option):         
        ''''enrypt the client keyexchange message  
        -> public encryption
        '''

        try:
            # extract information
            L().log(604, pub_enc_alg, pub_enc_keylen, size_to_enc)
            algorithm = EnumTrafor().to_value(pub_enc_alg)
            key_len = EnumTrafor().to_value(pub_enc_keylen)
            
            # read Database
            if pub_enc_alg == AsymAuthMechEnum.ECC: 
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_enc_client_keyex_msg'], mode='ENCRYPTION', param_len=key_len, alg=algorithm, data_size=size_to_enc, description='t_tls_hand_enc_client_keyex_msg')
            else: 
                if size_to_enc > ((float(key_len) / 8) - 11): 
                    size_to_enc_in = ceil((float(key_len) / 8) - 11)
                else:
                    size_to_enc_in = size_to_enc
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_enc_client_keyex_msg'], exp=pub_enc_alg_option, mode='ENCRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_enc_in, description='t_tls_hand_enc_client_keyex_msg')
                
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(size_to_enc / ((float(key_len) / 8) - 11))
                db_val = db_val * nr_chuncks
                
            # return result
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_tls_hand_enc_client_keyex_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_tls_hand_enc_client_keyex_msg'], size_to_enc, pub_enc_alg, pub_enc_keylen, pub_enc_alg_option]))
                L().log(603, 't_tls_hand_enc_client_keyex_msg')
        
            return 0.001  # self.settings['t_tls_hand_enc_client_keyex_msg'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_INNER'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_tls_hand_enc_client_keyex_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_tls_hand_enc_client_keyex_msg'], size_to_enc, pub_enc_alg, pub_enc_keylen, pub_enc_alg_option]))
            return 0.000000001
    
    
    def c_t_tls_hand_dec_client_keyex_msg(self, pub_dec_alg, pub_dec_keylen, size_to_dec, pub_dec_alg_option):
        ''' time to decrypt the inner registration message         
         -> So this is a private decryption with the sec module private key (after this was public encrypted)
        '''
        try:
            # extract infos
            L().log(701, pub_dec_alg, pub_dec_keylen, size_to_dec)        
            algorithm = EnumTrafor().to_value(pub_dec_alg)
            al_mode = EnumTrafor().to_value(pub_dec_alg_option)
            key_len = EnumTrafor().to_value(pub_dec_keylen) 
            
            # DB Lookup
            if pub_dec_alg == AsymAuthMechEnum.ECC: 
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_tls_hand_dec_client_keyex_msg'], mode='DECRYPTION', \
                                                       param_len=key_len, alg=algorithm, data_size=size_to_dec, description='t_tls_hand_dec_client_keyex_msg')
            else: 
                db_val = TimingDBMap().lookup_interpol(exp=al_mode, lib=self.library_tags['t_tls_hand_dec_client_keyex_msg'], mode='DECRYPTION', \
                                                       keylen=key_len, alg=algorithm, data_size=size_to_dec, description='t_tls_hand_dec_client_keyex_msg')
            
            # return result
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_tls_hand_dec_client_keyex_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_tls_hand_dec_client_keyex_msg'], pub_dec_alg, pub_dec_keylen, size_to_dec, pub_dec_alg_option]))
                L().log(603, 't_tls_hand_dec_client_keyex_msg')
    
            return 0.01  # self.settings['t_tls_hand_dec_client_keyex_msg'] = 'ecuSW.app_lay.ecu_auth.SSMA_DECR_INNER_REG_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_tls_hand_dec_client_keyex_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_tls_hand_dec_client_keyex_msg'], pub_dec_alg, pub_dec_keylen, size_to_dec, pub_dec_alg_option]))
            return 0.000000001
    
        
