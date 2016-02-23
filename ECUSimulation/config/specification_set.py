'''
Created on 17 Aug, 2015

@author: artur.mrowca
'''
from tools.singleton import Singleton
from enums.sec_cfg_enum import HashMechEnum, AsymAuthMechEnum, AuKeyLengthEnum, \
    SymAuthMechEnum, PRF
from components.security.encryption.encryption_tools import EncryptionSize
from components.base.ecu.software.impl_physical_layers import StdPhysicalLayer
from components.base.ecu.software.impl_datalink_layers import StdDatalinkLayer
from components.base.ecu.software.impl_transport_layers import StdTransportLayer, \
    FakeSegmentTransportLayer
from components.base.bus.impl_bus_can import StdCANBus
from enums.tls_enums import CompressionMethod


class GeneralSpecPreset(Singleton):
    
    def __init__(self):
        
        self.enabled = False
        
        self.physical_layer = StdPhysicalLayer
        self.datalink_layer = StdDatalinkLayer  # datalink layer that is used in all ECUs that implement this option
        self.transport_layer = FakeSegmentTransportLayer

        self.bus = StdCANBus
        
        self.disable_fallback_message = True
        
    def bus_string(self):
        return self.bus.__name__
        
    def enable(self):
        self.enabled = True

class TlsSpecPresets(Singleton):
    '''
    this class contains the predefined specification for certain libraries used in the
    Tls ECU Specifications. Those will lead to a working constellation.
    They can be applied first and customized then.
    '''

    def __init__(self):
        
        #===============================================================
        #     Record Layer
        #===============================================================
        # algorithms used by record layer (after negotiation)
        self.protocol_version = [3, 3]
        self.record_layer_spec = [CompressionMethod.NULL, HashMechEnum.MD5, AuKeyLengthEnum.bit_128, SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.CBC]
        
        #=======================================================================
        #     Handshake
        #=======================================================================
        
        # certificate specs
        self.server_certificate_spec = [AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 3, HashMechEnum.MD5, 1, 1000]
        self.client_certificate_spec = [AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 3, HashMechEnum.MD5, 1, 1000]
    
        # prf used for masterkey generation
        self.prf_master_key = PRF.DUMMY
        
        # finished message
        self.finished_message_spec = [HashMechEnum.MD5, PRF.DUMMY, PRF.DUMMY, PRF.DUMMY, PRF.DUMMY]
        
        #=======================================================================
        #     Sizes
        #=======================================================================
        self.mac_input_size = [60, 60 ]  # Input Size for the mac algorithm used in Record Layer at sending/receiveing side
        self.cert_verify_size = 100  # size of certificate verify message
        self.client_key_exchange_size = 100
        self.server_finished_size = [100, 100]  # size of server finished message on send and receive side
        self.client_finished_size = [100, 100]  # size of client finished message on send and receive side
        self.size_root_certificate = 1000
        
        self.client_hello_size = 60
        self.cert_request_size = 250
        self.server_hello_size = 60
        self.server_hello_done_size = 10
        
    def apply_spec(self, ecu_spec):
                
        ecu_spec.set_ecu_setting('p_tls_record_protocol_version', self.protocol_version)  # Protocol Version
        
        # Compression
        ecu_spec.set_ecu_setting('p_tls_record_compress_algorithm', self.record_layer_spec[0])  # Compression Algorithm used in Record Layer
        ecu_spec.set_ecu_setting('p_tls_record_mac_algorithm', self.record_layer_spec[1])  # MAC Algorithm used in Record Layer
        ecu_spec.set_ecu_setting('p_tls_record_mac_key_len', self.record_layer_spec[2])  # MAC Keylength used in Record Layer
        ecu_spec.set_ecu_setting('p_tls_record_enc_algorithm', self.record_layer_spec[3])  # Encryption Algorithm used in Record Layer
        ecu_spec.set_ecu_setting('p_tls_record_enc_key_len', self.record_layer_spec[4])  # Keylength of ALgorithm used in Record Layer
        ecu_spec.set_ecu_setting('p_tls_record_enc_algorithm_mode', self.record_layer_spec[5])  # Mode of algorithm used in Record Layer
                          
        # Server Certificate 
        ecu_spec.set_ecu_setting('p_tls_hand_server_cert_enc_algorithm', self.server_certificate_spec[0])  # Encryption Algorithm used in Server Certificate
        ecu_spec.set_ecu_setting('p_tls_hand_server_cert_enc_key_len', self.server_certificate_spec[1])  # Keylength for Encryption Algorithm used in Server Certificate  
        ecu_spec.set_ecu_setting('p_tls_hand_server_cert_enc_algorithm_option', self.server_certificate_spec[2])  # Option for Encryption Algorithm used in Server Certificate
        ecu_spec.set_ecu_setting('p_tls_hand_server_cert_hash_mech', self.server_certificate_spec[3])  # Hash algorithm used in the Server Certificate
        ecu_spec.set_ecu_setting('p_tls_hand_server_cert_ca_len', self.server_certificate_spec[4])
         
        # PRF Algorithm
        ecu_spec.set_ecu_setting('p_tls_hand_prf_master_generation', self.prf_master_key)  # PRF Algorithm used to create the master secret
        
        # Client certificate 
        ecu_spec.set_ecu_setting('p_tls_hand_client_cert_enc_algorithm', self.client_certificate_spec[0])
        ecu_spec.set_ecu_setting('p_tls_hand_client_cert_enc_key_len', self.client_certificate_spec[1])
        ecu_spec.set_ecu_setting('p_tls_hand_client_cert_enc_algorithm_option', self.client_certificate_spec[2])
        ecu_spec.set_ecu_setting('p_tls_hand_client_cert_unsigned_size', EncryptionSize().output_size(self.client_certificate_spec[5], self.client_certificate_spec[3], None, 'HASH'))
         
        # Finished message algorithms        
        ecu_spec.set_ecu_setting('p_tls_hand_finish_hash_algorithm', self.finished_message_spec[0])  # Hash algorithm used to create the verification hash in the client/server finished message
        ecu_spec.set_ecu_setting('p_tls_hand_server_finish_rec_prf_algorithm', self.finished_message_spec[1])  # PRF algorithm used to create the verification hash in the server finished message on receiving side
        ecu_spec.set_ecu_setting('p_tls_hand_server_finish_send_prf_algorithm', self.finished_message_spec[2])  # PRF algorithm used to create the verification hash in the server finished message on sending side
        ecu_spec.set_ecu_setting('p_tls_hand_client_finish_send_prf_algorithm', self.finished_message_spec[3])  # PRF algorithm used to create the verification hash in the client finished message on sending side
        ecu_spec.set_ecu_setting('p_tls_hand_client_finish_rec_prf_algorithm', self.finished_message_spec[4])  # PRF algorithm used to create the verification hash in the client finished message on receiving side
        
            
        #=======================================================================
        #     Sizes
        #=======================================================================    
        # Record Layer 
        # ecu_spec.set_ecu_setting('p_tls_record_compressed_size', 100) #automatically calculated: Size of message after being compressed used in Record Layer                
        ecu_spec.set_ecu_setting('p_tls_record_mac_inputsize', self.mac_input_size[0])  # Input Size for the mac algorithm used in Record Layer at sending side
        # ecu_spec.set_ecu_setting('p_tls_record_mac_outputsize', 100)  #automatically calculated: Output size of the mac algorithm used in Record Layer at sending side        
        # ecu_spec.set_ecu_setting('p_tls_record_enc_size', 100) #automatically calculated: Size of message after being encrypted in the record layer
        ecu_spec.set_ecu_setting('p_tls_record_dec_mac_inputsize', self.mac_input_size[1])  # Input Size for the mac algorithm used in Record Layer at receiving side
        # ecu_spec.set_ecu_setting('p_tls_record_dec_mac_outputsize', 100)  #automatically calculated: Output size of the mac algorithm used in Record Layer at receiving side
        
        # Handshake        
        # ecu_spec.set_ecu_setting('p_tls_hand_cert_verify_cipher_size', 100) # automatically calculated: Size of certificate Verify message after encryption
        ecu_spec.set_ecu_setting('p_tls_hand_cert_verify_clear_size', self.cert_verify_size)  # Size of certificate Verify message before encryption        
        ecu_spec.set_ecu_setting('p_tls_hand_server_cert_unsigned_size', EncryptionSize().output_size(self.server_certificate_spec[5], self.server_certificate_spec[3], None, 'HASH'))  # Size of the Server Certificate before Sign process
        # ecu_spec.set_ecu_setting('p_tls_hand_server_cert_signed_size',100) #automatically calculated: Size of the Signed Hash in the Server Certificate        
        
        # ecu_spec.set_ecu_setting('p_tls_hand_client_keyex_cipher_size', 100) # automatically calculated: Size of the client key exchange message after being encrypted     
        ecu_spec.set_ecu_setting('p_tls_hand_client_keyex_clear_size', self.client_key_exchange_size)  # Size of the client key exchange message before being encrypted                
        
        
        # ecu_spec.set_ecu_setting('p_tls_hand_server_finish_rec_hash_size', 100)  # automatically calculated: Size of the server finished message hash on the receiving side
        ecu_spec.set_ecu_setting('p_tls_hand_server_finish_rec_content_size', self.server_finished_size[1])  # Size of the server finished message content on the receiving side        
        # ecu_spec.set_ecu_setting('p_tls_hand_client_finish_rec_hash_size', 100)  # automatically calculated: Size of the client finished message hash on the receiving side
        ecu_spec.set_ecu_setting('p_tls_hand_client_finish_rec_content_size', self.client_finished_size[1])  # Size of the client finished message content on the receiving side
        # ecu_spec.set_ecu_setting('p_tls_hand_server_finish_send_hash_size', 100)  # automatically calculated: Size of the server finished message hash on the sending side
        ecu_spec.set_ecu_setting('p_tls_hand_server_finish_send_content_size', self.server_finished_size[0])  # Size of the server finished message content on the sending side        
        # ecu_spec.set_ecu_setting('p_tls_hand_client_finish_send_hash_size', 100)  # automatically calculated: Size of the client finished message hash on the sending side
        ecu_spec.set_ecu_setting('p_tls_hand_client_finish_send_content_size', self.client_finished_size[0])  # Size of the client finished message content on the sending side        
        
        ecu_spec.set_ecu_setting('p_tls_certificate_send_size', self.size_root_certificate)  # Size of one certificate (root certificate)
        
        # Sending size
        ecu_spec.set_ecu_setting('p_tls_hand_client_hello_size', self.client_hello_size)
        ecu_spec.set_ecu_setting('p_tls_hand_cert_request_send_size', self.cert_request_size)  # Sending size of a certificate request message         
        ecu_spec.set_ecu_setting('p_tls_hand_server_hello_send_size', self.server_hello_size)  # Sending size of server hello message 
        ecu_spec.set_ecu_setting('p_tls_hand_server_hello_done_send_size', self.server_hello_done_size)  # Sending size of a server hello done message 


class TeslaSpecPresets(Singleton):
    '''
    this class contains the predefined specification for certain libraries used in the
    Tesla ECU Specifications. Those will lead to a working constellation.
    They can be applied first and customized then.
    '''
    
    def __init__(self):
        
        # start time setup/ setup interval /number of generated keys on setup
        self.setup_spec = [0, 999999, 50000] 
          
        # Mac Algorithm
        self.mac_spec = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128]
    
        # Prf Methods
        self.prf_create_chain = PRF.DUMMY  # PRF Method used to create the Key Chain
        self.prf_generate_mac_key = PRF.DUMMY  # PRF Method used to generate the MAC Key
        
        # key exchange information
        self.key_exchange_spec = [AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 3, 100]  # algorithm to exchange initial key/ size of the key exchange message
        
        # key legislation specs
        self.key_legid_mac_spec = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128]  # MAC Algorithm used to check if key is legid
    
        # time to legitimate one key and to generate the mac used for comparison
        self.time_legitimate_key = False  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
        self.time_generate_compare_mac = False  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
        
    def apply_spec(self, ecu_spec):        
        
        ecu_spec.set_ecu_setting('p_start_setup_time', self.setup_spec[0])  # time when the setup will start
        ecu_spec.set_ecu_setting('p_repeat_setup_time', self.setup_spec[1])  # time when the setup will be repeated
        ecu_spec.set_ecu_setting('p_key_chain_len', self.setup_spec[2])  # number of keys that will be generated during the setup phase
        
        ecu_spec.set_ecu_setting('p_mac_key_algorithm', self.mac_spec[0])  # MAC Algorithm used for the messages
        ecu_spec.set_ecu_setting('p_mac_key_len', self.mac_spec[1])  # key length of the used MAC Algorithm
        
        ecu_spec.set_ecu_setting('p_prf_key_chain_method', self.prf_create_chain)  # PRF Method used to create the Key Chain
        ecu_spec.set_ecu_setting('p_prf_mac_key_method', self.prf_generate_mac_key)  # PRF Method used to generate the MAC Key
        
        # Initial Key exchange: Public/Private De/Encyption
        ecu_spec.set_ecu_setting('p_key_exchange_algorithm', self.key_exchange_spec[0])
        ecu_spec.set_ecu_setting('p_key_exchange_keylen', self.key_exchange_spec[1])
        ecu_spec.set_ecu_setting('p_key_exchange_algorithm_option', self.key_exchange_spec[2])        
        ecu_spec.set_ecu_setting('p_key_exchange_clear_size', self.key_exchange_spec[3])  # Clear Size of the key exchange message
        # ecu_spec.set_ecu_setting('p_key_exchange_cipher_size', 100)# automatically calculated: Cipher Size of the key exchange message
        
        # MAC Algorithm used to check if key is legid
        ecu_spec.set_ecu_setting('p_legid_mac_key_algorithm', self.key_legid_mac_spec[0])  
        ecu_spec.set_ecu_setting('p_legid_mac_key_len', self.key_legid_mac_spec[1])
        
        # ecu_spec.set_ecu_setting('p_mac_transmit_size', 100)# automatically calculated:  size of one MAC after encryption
        if self.time_legitimate_key:
            ecu_spec.set_ecu_setting('t_prf_for_key_legitimation', self.time_legitimate_key)  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
        if self.time_generate_compare_mac:
            ecu_spec.set_ecu_setting('t_generate_compare_mac', self.time_generate_compare_mac)  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
    
class LWASpecPresets(Singleton):
    '''
    this class contains the predefined specification for certain libraries used in the
    Lightweight Authentication ECU Specifications. Those will lead to a working constellation.
    They can be applied first and customized then.
    '''
    
    def __init__(self):
        #=======================================================================
        #  LIBRARY TO USE
        #=======================================================================
        self.preset_ecu = "CyaSSL"  # options: CyaSSL, Crypto_Lib
        self.preset_sec_mod = "CyaSSL" 
        
        #=======================================================================
        #  ECU Authentication
        #=======================================================================
        # General
        self.trigger_spec = [0, 99999999]  # authentication: start and interval
        
        # security module certificate
        self.sec_certificate_spec = [HashMechEnum.MD5, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, 1, 1000]  # security module certificate info
        
        # registration message
        self.registration_first_part = [AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, 100] 
        self.registration_second_part = [HashMechEnum.MD5, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537]
        self.ecu_certificate_spec = [HashMechEnum.MD5, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, 1, 1000]  # ecu certificate info
        
        # confirmation message
        self.confirmation_part = [100]  # msg size
                
        
        #=======================================================================
        #  STREAM AUTHORIZATION
        #=======================================================================
        self.ecu_key_info = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.CBC]
        self.hold_rule = [False, 10]  # hold on/off; minimal interval between two stream requests
        
        # request message
        self.request_spec = [100, 9999999999]  # size of reqmsg and timeout maximum
        
        # deny/grant message
        self.deny_spec = [100]
        self.grant_spec = [100]
                
        # session key information
        self.session_key_info = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.CBC]  # schreibe alle die verfuegbar sind auf
    
        
    
    def apply_spec(self, ecu_spec, typ):
        
        # set settings         
        self._standard_spec(ecu_spec, typ, self.trigger_spec, self.sec_certificate_spec, self.registration_first_part, self.registration_second_part, \
                            self.ecu_certificate_spec, self.confirmation_part, self.ecu_key_info, self.hold_rule, self.request_spec, self.session_key_info, self.deny_spec, self.grant_spec)
    
    
    def _standard_spec(self, ecu_spec, typ, trigger_spec, sec_certificate_spec, registration_first_part, registration_second_part, \
                       ecu_certificate_spec, confirmation_part, ecu_key_info, hold_rule, request_spec, session_key_info, deny_spec, grant_spec):
        ''' this method will set the standard cya ssl setting to the
            given ecu specification. All available options are listed here.
        
            Input:  ecu_spec       SimpleECUSpec      ECU spec that will be defined
                    ecu_func_set   TimingFunctions    timing functions set
                    typ            string             'sec_mod' or 'ecu'
            Output: -
        '''        
                        
        # CONFIGURATION FOR SECURITY MODULE
        if typ == 'sec_mod':
            
            #===============================================================================
            #  General settings
            #===============================================================================
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', trigger_spec[0])  # time when ECU Authentication is triggered
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', trigger_spec[1])  # interval in which the ECU advertisement message is sent
            
            #===============================================================================
            #  ECU Authentication
            #===============================================================================

            # ECU ADVERTISEMENT MESSAGE           
            ecu_spec.set_ecu_setting('p_sec_mod_cert_hashing_mech', sec_certificate_spec[0])  # Hashing mechanism used in certificate of security module (alternative: HashMechEnum.SHA1, HashMechEnum.SHA256)
            ecu_spec.set_ecu_setting('p_sec_mod_cert_enc_mech', sec_certificate_spec[1])  # Encryption mechanism used in certificate of security module (alternative: HashMechEnum.ECC)
            ecu_spec.set_ecu_setting('p_sec_mod_cert_enc_keylen', sec_certificate_spec[2])  # key length of encryption mechanism used in certificate of security module (alternative if RSA: bit_1024, bit_2048 // if ECC: bit_192, bit_384, bit_521)
            ecu_spec.set_ecu_setting('p_sec_mod_cert_enc_mech_option', sec_certificate_spec[3])  # addition to encryption mechanism used in certificate of security module (alternative if RSA: 3,5, 17, 257, 65537 // no alternative if ECC)
            ecu_spec.set_ecu_setting('p_sec_mod_cert_ca_len', sec_certificate_spec[4])  # number of certification authorities in the hierarchy until root CA
            ecu_spec.set_ecu_setting('p_sec_mod_cert_size', sec_certificate_spec[5])  # size of the certificate when sent
            ecu_spec.set_ecu_setting('p_sec_mod_cert_hash_size', EncryptionSize().output_size(sec_certificate_spec[5], sec_certificate_spec[0], None, 'HASH'))  # size of the certificate after being hashed
            ecu_spec.set_ecu_setting('p_sec_mod_cert_signed_hash_size', EncryptionSize().output_size(EncryptionSize().output_size(sec_certificate_spec[5], sec_certificate_spec[0], None, 'HASH'), sec_certificate_spec[1], sec_certificate_spec[2], 'SIGN'))  # size of the certificate after being signed (i.e. hashed and encrypted)                
            
            # REGISTRATION MESSAGE
            # first part            
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method', registration_first_part[0])  # Encryption mechanism used to encrypt the first part of the registration message (alternative: HashMechEnum.ECC) 
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_keylen', registration_first_part[1])  # key length of encryption mechanism used to encrypt the first part of the registration message (alternative if RSA: bit_1024, bit_2048 // if ECC: bit_192, bit_384, bit_521)
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method_option', registration_first_part[2])  # addition to encryption mechanism used to encrypt the first part of the registration message (alternative if RSA: 3,5, 17, 257, 65537 // no alternative if ECC)    
            ecu_spec.set_ecu_setting('p_reg_msg_inner_content_size', registration_first_part[3])  # size of the first part of the registration message before being encrypted
            # ecu_spec.set_ecu_setting('p_reg_msg_inner_cipher_size', 100) # automatically calculated: size of the first part of the registration message after being encrypted
            # ecu_spec.set_ecu_setting('t_ecu_auth_reg_msg_inner_dec', 0.5)# automatically calculated: time to decrypt the first part of the registration message
            # second part        
            ecu_spec.set_ecu_setting('p_reg_msg_hash_alg', registration_second_part[0])  # Hashing algorithm used to hash the outer registration message (alternative: HashMechEnum.SHA1, HashMechEnum.SHA256)            
            ecu_spec.set_ecu_setting('p_reg_msg_outter_enc_alg', registration_second_part[1])  # Encryption mechanism used to encrypt the hashed second part of the registration message (alternative: HashMechEnum.ECC)
            ecu_spec.set_ecu_setting('p_reg_msg_outter_enc_alg_option', registration_second_part[3])  # addition to encryption mechanism used to encrypt the hashed second part of the registration message  (alternative if RSA: 3,5, 17, 257, 65537 // no alternative if ECC)     
            ecu_spec.set_ecu_setting('p_reg_msg_outter_enc_keylen', registration_second_part[2])  # key length of encryption mechanism used to encrypt the hashed second part of the registration message (alternative if RSA: bit_1024, bit_2048 // if ECC: bit_192, bit_384, bit_521)
            ecu_spec.set_ecu_setting('t_ecu_auth_reg_msg_comp_hash_process', 0)  # time needed to compare the received hash to the created hash
            # ecu_spec.set_ecu_setting('p_reg_msg_outter_cipher_size', 100) # automatically calculated: size of the second part of the registration message after being hashed and encrypted/signed 
            # ecu_spec.set_ecu_setting('p_reg_msg_outter_hash_size' # automatically calculated: size of the second part of the registration message after being hashed 
            # ecu_spec.set_ecu_setting('t_ecu_auth_reg_msg_create_comp_hash', 0.5) # time to create the hash in the registration message that is used for the comparison of hashes
            # ecu_spec.set_ecu_setting('t_ecu_auth_reg_msg_outter_dec', 0.5)# automatically calculated: time to decrypt the second part of the registration message
            # third part
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_mech', ecu_certificate_spec[0])  # Hashing mechanism used in certificate of the ecu (alternative: HashMechEnum.SHA1, HashMechEnum.SHA256)
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_mech', ecu_certificate_spec[1])  # Encryption mechanism used in certificate of the ecu (alternative: HashMechEnum.ECC)
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_mech_option', ecu_certificate_spec[3])  # addition to encryption mechanism used in certificate of the ecu (alternative if RSA: 3,5, 17, 257, 65537 // no alternative if ECC)
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_keylen', ecu_certificate_spec[2])  # key length of encryption mechanism used in certificate of the ecu (alternative if RSA: bit_1024, bit_2048 // if ECC: bit_192, bit_384, bit_521)
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_ca_len', ecu_certificate_spec[4])  # number of certification authorities in the hierarchy until root CA
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_unsigned_size', EncryptionSize().output_size(ecu_certificate_spec[5], ecu_certificate_spec[0], None, 'HASH'))  # size of the certificate after being hashed
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_signed_size', EncryptionSize().output_size(EncryptionSize().output_size(ecu_certificate_spec[5], ecu_certificate_spec[0], None, 'HASH'), ecu_certificate_spec[1], ecu_certificate_spec[2], 'SIGN'))  # size of the certificate after being signed (i.e. hashed and encrypted)  
            # ecu_spec.set_ecu_setting('t_ecu_auth_reg_msg_validate_cert', 5) # automatically calculated: time to validate the ECU certificate that was received
            
            # CONFIRMATION MESSAGE
            ecu_spec.set_ecu_setting('p_ecu_auth_conf_msg_size', confirmation_part[0])  # size of the confirmation message before encryption            
            # ecu_spec.set_ecu_setting('p_sec_mod_conf_msg_sending_size', 128)# automatically calculated: size of the confirmation message after encryption  
            # ecu_spec.set_ecu_setting('t_ecu_auth_conf_msg_enc', 0.5)# automatically calculated: time do encrypt the confirmation message
                    
            #===============================================================================
            #  Stream Authorization
            #===============================================================================
            
            # REQUEST MESSAGE            
            ecu_spec.set_ecu_setting('p_req_msg_content_size', request_spec[0])  # size of the content of the request message
            # ecu_spec.set_ecu_setting('p_req_msg_cipher_size', 250) # automatically calculated: size of the request message after being encrypted
            # ecu_spec.set_ecu_setting('t_str_auth_decr_req_msg', 0.5)# automatically calculated: time to decrypt the request message
            
            # DENY MESSAGE
            
            ecu_spec.set_ecu_setting('p_str_auth_deny_msg_sending_size', deny_spec[0])
            # ecu_spec.set_ecu_setting('t_str_auth_enc_deny_msg', 0.5) # automatically calculated: time to encrypt the deny message
                                     
            # GRANT MESSAGE            
            ecu_spec.set_ecu_setting('p_grant_msg_content_size', grant_spec[0])  # size of the grant message before being encrypted
            # ecu_spec.set_ecu_setting('p_str_auth_grant_msg_sending_size', 100)# automatically calculated: size of the grant message after being encrypted
            # ecu_spec.set_ecu_setting('t_str_auth_keygen_grant_msg', 0.5)  # automatically calculated: time to generate the session key sent via the grant message
            # ecu_spec.set_ecu_setting('t_str_auth_enc_grant_msg', 0.5) # automatically calculated: time to encrypt the grant message
                
            # SESSION KEY
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_enc_alg', session_key_info[0])  # algorithm used for the session key
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_enc_alg_mode', session_key_info[2])  # algorithm mode used for the session key
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_enc_keylen', session_key_info[1])  # algorithm key length used for the session key 
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_validity', 9999999999)  # validity of the session key
    
    
        # CONFIGURATION FOR ECU
        if typ == 'ecu':
            
            #=======================================================================
            #     ECU Authentication
            #=======================================================================         
            # ECU ADVERTISEMENT
            ecu_spec.set_ecu_setting('p_sec_mod_cert_size', sec_certificate_spec[5])  # size of the certificate when sent                                     
            ecu_spec.set_ecu_setting('p_sec_mod_cert_hashing_mech', sec_certificate_spec[0])  # Hashing mechanism used in certificate of security module (alternative: HashMechEnum.SHA1, HashMechEnum.SHA256)
            ecu_spec.set_ecu_setting('p_sec_mod_cert_enc_mech', sec_certificate_spec[1])  # Encryption mechanism used in certificate of security module (alternative: HashMechEnum.ECC)
            ecu_spec.set_ecu_setting('p_sec_mod_cert_enc_keylen', sec_certificate_spec[2])  # key length of encryption mechanism used in certificate of security module (alternative if RSA: bit_1024, bit_2048 // if ECC: bit_192, bit_384, bit_521)
            ecu_spec.set_ecu_setting('p_sec_mod_cert_enc_mech_option', sec_certificate_spec[3])  # addition to encryption mechanism used in certificate of security module (alternative if RSA: 3,5, 17, 257, 65537 // no alternative if ECC)
            ecu_spec.set_ecu_setting('p_sec_mod_cert_ca_len', sec_certificate_spec[4])  # number of certification authorities in the hierarchy until root CA
            ecu_spec.set_ecu_setting('p_sec_mod_cert_hash_size', EncryptionSize().output_size(sec_certificate_spec[5], sec_certificate_spec[0], None, 'HASH'))  # size of the certificate after being hashed
            ecu_spec.set_ecu_setting('p_sec_mod_cert_signed_hash_size', EncryptionSize().output_size(EncryptionSize().output_size(sec_certificate_spec[5], sec_certificate_spec[0], None, 'HASH'), sec_certificate_spec[1], sec_certificate_spec[2], 'SIGN'))  # size of the certificate after being signed (i.e. hashed and encrypted)  
            # ecu_spec.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.5) # automatically calculated: time to verify the Security Module certificate

            # REGISTRATION MESSAGE
            # ecu_spec.set_ecu_setting('t_reg_msg_sym_keygen', 0.5)  # automatically calculated: time to generate the symmetric ECU key sent in the registration message
            # first part
            ecu_spec.set_ecu_setting('p_reg_msg_inner_content_size', registration_first_part[3])  # size of the first part of the registration message before being encrypted
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_keylen', registration_first_part[1])  # key length of encryption mechanism used to encrypt the first part of the registration message (alternative if RSA: bit_1024, bit_2048 // if ECC: bit_192, bit_384, bit_521)
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method', registration_first_part[0])  # Encryption mechanism used to encrypt the first part of the registration message (alternative: HashMechEnum.ECC)
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method_option', registration_first_part[2])  # addition to encryption mechanism used to encrypt the first part of the registration message (alternative if RSA: 3,5, 17, 257, 65537 // no alternative if ECC)     
            # ecu_spec.set_ecu_setting('p_reg_msg_inner_cipher_size', 100) # automatically calculated: size of the first part of the registration message after being encrypted
            # ecu_spec.set_ecu_setting('t_reg_msg_inner_enc', 0.5)  # automatically calculated: time to encrypt the inner registration message
            # second part
            # ecu_spec.set_ecu_setting('p_reg_msg_outter_cipher_size', 100) # automatically calculated: size of the second part of the registration message after being encrypted
            
            ecu_spec.set_ecu_setting('p_reg_msg_hash_alg', registration_second_part[0])  # Hashing algorithm used to hash the outer registration message (alternative: HashMechEnum.SHA1, HashMechEnum.SHA256)        
            ecu_spec.set_ecu_setting('p_reg_msg_outter_enc_alg', registration_second_part[1])  # Encryption mechanism used to encrypt the hashed second part of the registration message (alternative: HashMechEnum.ECC)
            ecu_spec.set_ecu_setting('p_reg_msg_outter_enc_alg_option', registration_second_part[3])  # addition to encryption mechanism used to encrypt the hashed second part of the registration message  (alternative if RSA: 3,5, 17, 257, 65537 // no alternative if ECC)     
            ecu_spec.set_ecu_setting('p_reg_msg_outter_enc_keylen', registration_second_part[2])  # key length of encryption mechanism used to encrypt the hashed second part of the registration message (alternative if RSA: bit_1024, bit_2048 // if ECC: bit_192, bit_384, bit_521)
            # ecu_spec.set_ecu_setting('p_reg_msg_outter_hash_size' # automatically calculated: size of the second part of the registration message after being hashed 
            # ecu_spec.set_ecu_setting('t_reg_msg_hash', 0.5) # automatically calculated: time to hash the second part of the registration message
            # ecu_spec.set_ecu_setting('t_reg_msg_outter_enc', 0.5) # automatically calculated: time to encrypt the hashed second part of the registration message
            # third part
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_mech', ecu_certificate_spec[0])  # Hashing mechanism used in certificate of the ecu (alternative: HashMechEnum.SHA1, HashMechEnum.SHA256)
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_mech', ecu_certificate_spec[1])  # Encryption mechanism used in certificate of the ecu (alternative: HashMechEnum.ECC)
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_mech_option', ecu_certificate_spec[3])  # addition to encryption mechanism used in certificate of the ecu (alternative if RSA: 3,5, 17, 257, 65537 // no alternative if ECC)
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_keylen', ecu_certificate_spec[2])  # key length of encryption mechanism used in certificate of the ecu (alternative if RSA: bit_1024, bit_2048 // if ECC: bit_192, bit_384, bit_521)
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_ca_len', ecu_certificate_spec[4])  # number of certification authorities in the hierarchy until root CA
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_unsigned_size', EncryptionSize().output_size(ecu_certificate_spec[5], ecu_certificate_spec[0], None, 'HASH'))  # size of the certificate after being hashed
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_signed_size', EncryptionSize().output_size(EncryptionSize().output_size(ecu_certificate_spec[5], ecu_certificate_spec[0], None, 'HASH'), ecu_certificate_spec[1], ecu_certificate_spec[2], 'SIGN'))  # size of the certificate after being signed (i.e. hashed and encrypted)              
            ecu_spec.set_ecu_setting('p_ecu_cert_sending_size', ecu_certificate_spec[5])  # size of the ECU certificate when sent
            # ecu_spec.set_ecu_setting('p_reg_msg_sending_size', 1000) # automatically calculated: size of the registration message when sent 

            # CONFIRMATION MESSAGE
            ecu_spec.set_ecu_setting('p_ecu_auth_conf_msg_size', confirmation_part[0])  # size of the confirmation message before encryption
            # ecu_spec.set_ecu_setting('t_conf_msg_dec_time', 0.5) # automatically calculated: time to decrypt the confirmation message
            # ecu_spec.set_ecu_setting('p_conf_msg_cipher_size', 100)# automatically calculated: size of the encrypted confirmation message
            
            #===============================================================================
            #     Stream Authorization
            #===============================================================================
            # GENERAL
            ecu_spec.set_ecu_setting('p_ecu_sym_key_alg', ecu_key_info[0])  # Symmetric Key of ECU (Encryption Algorithm) used for ECU Authentication e.g. for confirmation message decryption
            ecu_spec.set_ecu_setting('p_ecu_sym_key_alg_mode', ecu_key_info[2])  # Symmetric Key of ECU (Encryption Algorithm Mode) used for ECU Authentication e.g. for confirmation message decryption
            ecu_spec.set_ecu_setting('p_ecu_sym_key_keylen', ecu_key_info[1])  # Symmetric Key of ECU (Encryption Algorithm Key length) used for ECU Authentication e.g. for confirmation message decryption
            ecu_spec.set_ecu_setting('p_stream_hold', hold_rule[0])  # if true messages are held until the authentication is complete else they are dropped
            ecu_spec.set_ecu_setting('p_stream_req_min_interval', hold_rule[1])  # minimal interval between two stream requests
            
            # REQUEST MESSAGE 
            ecu_spec.set_ecu_setting('t_req_msg_max_timeout', request_spec[1])  # Timeout when no request response received
            ecu_spec.set_ecu_setting('p_req_msg_content_size', request_spec[0])  # size of the content of the request message
            # ecu_spec.set_ecu_setting('p_req_msg_cipher_size', 250) # automatically calculated: size of the request message after being encrypted
            # ecu_spec.set_ecu_setting('p_req_msg_sending_size', 100) # automatically calculated: size of the request message after being encrypted
            # ecu_spec.set_ecu_setting('t_req_msg_stream_enc', 0.5) # automatically calculated: time to encrypt the request message
            
            # GRANT MESSAGE
            ecu_spec.set_ecu_setting('p_grant_msg_content_size', grant_spec[0])  # size of the grant message before being encrypted
            # ecu_spec.set_ecu_setting('t_grant_msg_stream_dec', 0.5)  # automatically calculated: time to decrypt the grant message
            # ecu_spec.set_ecu_setting('p_grant_msg_cipher_size', 100)  # automatically calculated: size of the grant message after being encrypted
            
            # DENY MESSAGE
            # ecu_spec.set_ecu_setting('t_deny_msg_stream_dec', 0.5)  # automatically calculated: time to decrypt the deny message
            
            # NORMAL MESSAGE
            # ecu_spec.set_ecu_setting('t_normal_msg_dec', 0.5) # automatically calculated: time to decrypt a normal message with the session key
            # ecu_spec.set_ecu_setting('t_normal_msg_enc', 0.5) # automatically calculated: time to encrypt a normal message with the session key
                                     
            
