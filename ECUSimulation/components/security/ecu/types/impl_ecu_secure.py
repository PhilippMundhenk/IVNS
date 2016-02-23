from components.base.ecu.software.ecu_software import ECUSoftware
from components.base.ecu.types.impl_ecu_simple import SimpleECU
from components.security.ecu.software.impl_comm_module_secure import SecureCommModule
from config.timing_db_admin import TimingDBMap
from enums.sec_cfg_enum import EnumTrafor, AsymAuthMechEnum
from tools.ecu_logging import ECULogger as L
from tools.general import General as G
import math
from math import ceil
import logging
from components.security.ecu.software.impl_app_layer_secure import SecureApplicationLayer


class SecureECU(SimpleECU):
    
    TEST_TIMES = []
    
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
        
        # no instantiation
        if sim_env == None: return  
        
        # set SW and HW
        SimpleECU.__init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer)                
        
        # create software
        self.ecuSW = ECUSoftware(sim_env, SecureCommModule(sim_env, ecu_id), SecureApplicationLayer(sim_env, ecu_id))
        
        # connect
        self._connect_hw_sw()                
        
    
    def set_security_set_from_rm(self, certificate_manager):
        ''' as certification constellations can be predefined in the
            certificate manager object this method can be used to set
            the ECUs configuration from this object. Thereby the ECUs
            certificate and all root certificates that this ECU has are 
            set
            
            Input:  certificate_manager    CertificateManager     manager object that has a predefined certificate constellation
            Output: -
        '''
        # set ECU certificate
        try:            
            certificate = certificate_manager.ecu_cert[self.ecu_id]
            self.ecuSW.comm_mod.authenticator.ecu_certificate = certificate
        except:
            pass
        
        try:           
            # set root certificates 
            root_certs = certificate_manager.ecu_root_cert[self.ecu_id]  
            self.ecuSW.comm_mod.authenticator.lst_root_cert = root_certs
        except:
            L().log(600, self.ecu_id)
        
    
    def get_type_id(self):
        ''' returns the id of this ECU type
        
            Input:    -
            Output:   ecu_type    string    type of this ECU; e.g.'TLSECU'
        '''
        return "Secure_ECU"
    
    
    def set_authenticated(self, authenticated):
        ''' this method will set the ECU Authentication ECU already
            authenticated so that no ECU Authentication needs to be performed
            
            Input:    authenticated        boolean        sets if the ecu needs to be authenticated
            Output:   - 
        '''
        self._authenticated = authenticated
        self.ecuSW.comm_mod.set_authenticated(authenticated)
    
    
    def is_authenticated(self):
        ''' returns if the ecu was already authenticated 
            or not
            
            Input:    -
            Output:   authenticated    boolean    true if authenticated
        '''
        return self._authenticated 

    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}

        #=======================================================================
        #     Sending sizes
        #=======================================================================
        self.settings['p_req_msg_sending_size'] = 'ecuSW.comm_mod.authorizer.SCCM_ECU_REQ_MSG_SIZE'  # Should be same as SSMA_SIZE_REQ_MSG_CIPHER   
        self.settings['p_reg_msg_sending_size'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_REG_MSG_SIZE' 
        self.settings['p_ecu_cert_sending_size'] = 'ecuSW.comm_mod.authenticator.ECU_CERT_SIZE'

        #=======================================================================
        #     Certification
        #=======================================================================
        # Own certification
        self.settings['p_ecu_auth_cert_hash_mech'] = 'ecuSW.comm_mod.authenticator.ECU_CERT_HASHING_MECH'
        self.settings['p_ecu_auth_cert_enc_mech'] = 'ecuSW.comm_mod.authenticator.ECU_CERT_ENCRYPTION_MECH'
        self.settings['p_ecu_auth_cert_enc_mech_option'] = 'ecuSW.comm_mod.authenticator.ECU_CERT_ENCRYPTION_MECH_OPTION'
        self.settings['p_ecu_auth_cert_enc_keylen'] = 'ecuSW.comm_mod.authenticator.ECU_CERT_KEYL'
        self.settings['p_ecu_auth_cert_ca_len'] = 'ecuSW.comm_mod.authenticator.ECU_CERT_CA_LEN'
        self.settings['p_ecu_auth_cert_hash_unsigned_size'] = 'ecuSW.comm_mod.authenticator.ECU_CERT_SIZE_HASH_TO_SIGN'
        self.settings['p_ecu_auth_cert_hash_signed_size'] = 'ecuSW.comm_mod.authenticator.ECU_CERT_SIZE_HASH_SIGNED'
        self.settings['p_reg_msg_inner_cipher_size'] = 'ecuSW.comm_mod.authenticator.SSMA_REG_MSG_CIPHER_SIZE_INNER'
        self.settings['p_reg_msg_outter_cipher_size'] = 'ecuSW.comm_mod.authenticator.SSMA_REG_MSG_CIPHER_SIZE_OUTER'
        
        # Certification of sec module certificate
        self.settings['p_sec_mod_cert_hashing_mech'] = 'ecuSW.comm_mod.authenticator.SECMOD_CERT_HASHING_MECH'
        self.settings['p_sec_mod_cert_enc_mech'] = 'ecuSW.comm_mod.authenticator.SECMOD_CERT_ENCRYPTION_MECH'
        self.settings['p_sec_mod_cert_enc_mech_option'] = 'ecuSW.comm_mod.authenticator.SECMOD_CERT_ENCRYPTION_MECH_OPTION'
        self.settings['p_sec_mod_cert_enc_keylen'] = 'ecuSW.comm_mod.authenticator.SECMOD_CERT_KEYL'
        self.settings['p_sec_mod_cert_ca_len'] = 'ecuSW.comm_mod.authenticator.SECMOD_CERT_CA_LEN'
        self.settings['p_sec_mod_cert_hash_size'] = 'ecuSW.comm_mod.authenticator.SECMOD_CERT_SIZE_HASH_TO_SIGN'
        self.settings['p_sec_mod_cert_signed_hash_size'] = 'ecuSW.comm_mod.authenticator.SECMOD_CERT_SIZE_HASH_SIGNED'
        
        #=======================================================================
        #     ECU Authentication
        #=======================================================================    
        # Symmetric Key of ECU (Encryption Algorithm) used for ECU Authentication e.g. for confirmation message decryption
        self.settings['p_ecu_sym_key_alg'] = 'ecuSW.comm_mod.ecu_sym_enc_alg'  # SCCM_ECU_SYM_KEY_ENC_ALG
        self.settings['p_ecu_sym_key_alg_mode'] = 'ecuSW.comm_mod.ecu_sym_enc_alg_mode'  # SCCM_ECU_SYM_KEY_ENC_ALG_MODE
        self.settings['p_ecu_sym_key_keylen'] = 'ecuSW.comm_mod.ecu_sym_enc_keyl'  # SCCM_ECU_SYM_KEY_ENC_KEY_LEN

        # Asymmetric Algorithm used in the ECUs comm Module
        self.settings['p_reg_msg_outter_enc_alg'] = 'ecuSW.comm_mod.assym_enc_alg'  # SCCM_ECU_PUB_ENC_ALG
        self.settings['p_reg_msg_outter_enc_alg_option'] = 'ecuSW.comm_mod.assym_enc_alg_option'  # SCCM_ECU_PUB_ENC_ALG_OPTION
        self.settings['p_reg_msg_outter_enc_keylen'] = 'ecuSW.comm_mod.assym_enc_key_len'  # SCCM_ECU_PUB_ENC_KEY_LEN
        
        # Process Advertisement message
        self.settings['t_adv_msg_secmodcert_enc'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ADV_SEC_MOD_CERT_VAL'
                
        # Registration message
        self.settings['t_reg_msg_sym_keygen'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY'
        self.settings['t_reg_msg_inner_enc'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_INNER'
        self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        self.settings['t_reg_msg_outter_enc'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_OUTTER'
        
        self.settings['p_reg_msg_hash_alg'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_REG_MSG_HASH'
        self.settings['p_reg_msg_inner_enc_method'] = 'ecuSW.comm_mod.authenticator.SSMA_SECM_PUB_ENC_ALG'
        self.settings['p_reg_msg_inner_enc_method_option'] = 'ecuSW.comm_mod.authenticator.SSMA_SECM_PUB_ENC_ALG_OPTION'
        
        self.settings['p_reg_msg_inner_enc_keylen'] = 'ecuSW.comm_mod.authenticator.SSMA_SECM_PUB_ENC_KEY_LEN'
        self.settings['p_reg_msg_outter_hash_size'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_REG_MSG_HASH_LEN'
        self.settings['p_reg_msg_inner_content_size'] = 'ecuSW.comm_mod.authenticator.SSMA_REG_MSG_CT_SIZE_INNER'

        # Confirmation message                    
        self.settings['t_conf_msg_dec_time'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_DEC_CONF_MSG'    
        self.settings['p_conf_msg_cipher_size'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_CONF_MSG_CIPHER_SIZE'
        self.settings['p_ecu_auth_conf_msg_size'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_CONF_MSG_SIZE'
        
        #===============================================================================
        #     Stream Authorization
        #===============================================================================
        
        # Timeout when no request response received
        self.settings['t_req_msg_max_timeout'] = 'ecuSW.comm_mod.SCCM_MAX_WAIT_TIMEOUT'

        # Request message
        self.settings['t_req_msg_stream_enc'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_ENC_REQ_MSG'

        self.settings['p_req_msg_content_size'] = 'ecuSW.comm_mod.authorizer.SSMA_SIZE_REQ_MSG_CONTENT'
        self.settings['p_req_msg_cipher_size'] = 'ecuSW.comm_mod.authorizer.SSMA_SIZE_REQ_MSG_CIPHER'        
        
        # normal message
        self.settings['t_normal_msg_dec'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY'
        self.settings['t_normal_msg_enc'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY'

        # deny/grant message
        self.settings['t_deny_msg_stream_dec'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_DEC_DENY_MSG'
        self.settings['t_grant_msg_stream_dec'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_DEC_GRANT_MSG'

        self.settings['p_grant_msg_content_size'] = 'ecuSW.comm_mod.authorizer.SSMA_GRANT_MSG_CT_SIZE'        
        self.settings['p_grant_msg_cipher_size'] = 'ecuSW.comm_mod.authorizer.SSMA_GRANT_MSG_CIPHER_SIZE' 
        
        self.settings['p_stream_hold'] = 'ecuSW.comm_mod.authorizer.SSMA_STREAM_HOLD'        
        self.settings['p_stream_req_min_interval'] = 'ecuSW.comm_mod.authorizer.SSMA_STREAM_MIN_INTERVAL' 
        
        return self.settings
        
    @property
    
    def ecu_id(self):
        return self._ecu_id
    
    @ecu_id.setter
    
    def ecu_id(self, value):
        self._ecu_id = value   
        self.ecuSW.comm_mod.ecu_id = value
 
    
    def monitor_update(self):
        ''' returns a list of monitor inputs
            
            Input:    -
            Output:   list    list    list of MonitorInput objects
        '''
        return self.ecuSW.comm_mod.monitor_update()

class StdSecurECUTimingFunctions(object):
    ''' If used this class defines the timing behaviour
        
        Looks up values in the measurements.db
        if no value is found tries to interpolate it from neighbours
    '''

    def __init__(self, main_library_tag='CyaSSL'):
        ''' Constructor
            
            Input:  main_library_tag    string    tag of the library that will be used for     
                                                    access of the timing values per default
            Output: -
        '''
        # tags
        self.available_tags = ['CyaSSL', 'Crypto_Lib_HW', 'Crypto_Lib_SW']

        # fallback 
        self.fallback = ['CyaSSL', 'Crypto_Lib_HW', 'Crypto_Lib_SW']

        self.library_tag = main_library_tag  # e.g. CyaSSL, or CryptoLib
        
        # function map
        self.function_map = {}
        self.function_map['t_reg_msg_sym_keygen'] = self.c_t_reg_msg_sym_keygen
        self.function_map['t_reg_msg_inner_enc'] = self.c_t_reg_msg_inner_enc
        self.function_map['t_reg_msg_hash'] = self.c_t_reg_msg_hash
        self.function_map['t_reg_msg_outter_enc'] = self.c_t_reg_msg_outter_enc
        self.function_map['t_adv_msg_secmodcert_enc'] = self.c_t_adv_msg_secmodcert_enc
        self.function_map['t_conf_msg_dec_time'] = self.c_t_conf_msg_dec_time
        self.function_map['t_normal_msg_dec'] = self.c_t_normal_msg_dec
        self.function_map['t_normal_msg_enc'] = self.c_t_normal_msg_enc
        self.function_map['t_req_msg_stream_enc'] = self.c_t_req_msg_stream_enc
        self.function_map['t_deny_msg_stream_dec'] = self.c_t_deny_msg_stream_dec
        self.function_map['t_grant_msg_stream_dec'] = self.c_t_grant_msg_stream_dec

        # library tag per setting
        self.library_tags = {}
        self.library_tags['t_reg_msg_sym_keygen'] = self.library_tag
        self.library_tags['t_reg_msg_inner_enc'] = self.library_tag
        self.library_tags['t_reg_msg_hash'] = self.library_tag
        self.library_tags['t_reg_msg_outter_enc'] = self.library_tag
        self.library_tags['t_adv_msg_secmodcert_enc'] = self.library_tag
        self.library_tags['t_conf_msg_dec_time'] = self.library_tag
        self.library_tags['t_normal_msg_dec'] = self.library_tag
        self.library_tags['t_normal_msg_enc'] = self.library_tag
        self.library_tags['t_req_msg_stream_enc'] = self.library_tag
        self.library_tags['t_deny_msg_stream_dec'] = self.library_tag
        self.library_tags['t_grant_msg_stream_dec'] = self.library_tag
    
    
    def get_function_map(self):
        ''' returns the function_map that maps the timing parameters to 
            functions that are called when the timing parameters are accessed
            
            Input:    -
            Output:   function_map    dictionary        maps timing parameters to functions. 
                                                        Key:     settings identifier
                                                        Value:   method called for this setting 
        '''
        return self.function_map

    
    def c_t_adv_msg_secmodcert_enc(self, cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn, cert_size):
        ''' time to validate the certificates of the security module '''
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
                db_value = TimingDBMap().lookup_interpol(lib=self.library_tags['t_adv_msg_secmodcert_enc'], mode='VERIFY', param_len=key_length, alg=algorithm, data_size=cert_size_hashtosign, description='t_adv_msg_secmodcert_enc')                
            
            if self.library_tags['t_adv_msg_secmodcert_enc'] in ["Crypto_Lib_SW", "Crypto_Lib_HW"] and cert_enc_mech == AsymAuthMechEnum.RSA:  
                # 1. create hash of certificate content
                db_val_1 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_adv_msg_secmodcert_enc'], mode='HASH', alg=hash_algorithm, data_size=cert_size, description='t_adv_msg_secmodcert_enc')
                
                # 2. decrypt digital signature (signed hash size) using public key of certificate (public key operation -> similar to public encrypt)
                if cert_size_hashsigned > ((key_length / 8) - 11): 
                    cert_size_hashsigned_in = ceil((float(key_length) / 8) - 11)
                else:
                    cert_size_hashsigned_in = cert_size_hashsigned
                db_val_2 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_adv_msg_secmodcert_enc'], mode='VERIFY', keylen=key_length, alg=algorithm, data_size=cert_size_hashsigned_in, exp=cert_alg_optn, description='t_adv_msg_secmodcert_enc')     
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(cert_size_hashsigned / ((float(key_length) / 8) - 11))
                db_val_2 = db_val_2 * nr_chuncks
                
                # 3. create hash of digital signature                 
                db_val_3 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_adv_msg_secmodcert_enc'], mode='HASH', alg=hash_algorithm, data_size=cert_size_hashtosign, description='t_adv_msg_secmodcert_enc')
                
                
                db_value = db_val_1 + db_val_2 + db_val_3    
    
            if self.library_tags['t_adv_msg_secmodcert_enc'] == "CyaSSL" and cert_enc_mech == AsymAuthMechEnum.RSA:  
                # 1. create hash of certificate content
                db_val_1 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_adv_msg_secmodcert_enc'], mode='HASH', alg=hash_algorithm, data_size=cert_size, description='t_adv_msg_secmodcert_enc')
                
                # 2. decrypt digital signature (signed hash size) using public key of certificate (public key operation -> similar to public encrypt)
                if cert_size_hashsigned > ((key_length / 8) - 11): 
                    cert_size_hashsigned_in = ceil((float(key_length) / 8) - 11)
                else:
                    cert_size_hashsigned_in = cert_size_hashsigned
                db_val_2 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_adv_msg_secmodcert_enc'], mode='ENCRYPTION', keylen=key_length, alg=algorithm, data_size=cert_size_hashsigned_in, exp=cert_alg_optn, description='t_adv_msg_secmodcert_enc')     
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(cert_size_hashsigned / ((float(key_length) / 8) - 11))
                db_val_2 = db_val_2 * nr_chuncks
                
                # 3. create hash of digital signature                 
                db_val_3 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_adv_msg_secmodcert_enc'], mode='HASH', alg=hash_algorithm, data_size=cert_size_hashtosign, description='t_adv_msg_secmodcert_enc')
                
                
                db_value = db_val_1 + db_val_2 + db_val_3
    
            # Set value
            if db_value: 
                L().log(602, db_value)           
            else:
                logging.warn("Error: Could not find in DB the Value in 't_adv_msg_secmodcert_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_adv_msg_secmodcert_enc'], cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn]))
                return G().val_log_info(0.0000000001 , 603, 't_adv_msg_secmodcert_enc')
    
            # repeat cert_ca_len times
            abs_time = cert_ca_len * db_value
            
            return abs_time  # self.settings['t_adv_msg_secmodcert_enc'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ADV_SEC_MOD_CERT_VAL'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_adv_msg_secmodcert_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_adv_msg_secmodcert_enc'], cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn]))
            return 0.000000001
    
    
    def c_t_reg_msg_sym_keygen(self, sym_enc_alg, sym_enc_keylen):
        ''''time to create the symmetric ECU Key'''        
        # self.settings['t_reg_msg_sym_keygen'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY'
        
        try:
            # extract information
            L().log(604, sym_enc_alg, sym_enc_keylen, 0)
            algorithm = EnumTrafor().to_value(sym_enc_alg)
            key_len = EnumTrafor().to_value(sym_enc_keylen)
            
            # read Database
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_reg_msg_sym_keygen'], mode='KEYGEN', keylen=key_len, alg=algorithm, description='t_reg_msg_sym_keygen')
            
            # return result
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_reg_msg_sym_keygen' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_reg_msg_sym_keygen'], sym_enc_alg, sym_enc_keylen]))
                L().log(603, 't_reg_msg_sym_keygen')
        
            return 0.001
        except:
            logging.warn("Error: Could not find in DB the Value in 't_reg_msg_sym_keygen' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_reg_msg_sym_keygen'], sym_enc_alg, sym_enc_keylen]))
            return 0.000000001

    
    def c_t_reg_msg_inner_enc(self, size_to_enc, pub_enc_alg, pub_enc_keylen, pub_enc_alg_option):         
        ''''enrypt the inner part of the reg msg i.e. [sec_id, sym_key, nonce, timestamp]        
        -> public encryption
        '''

        try:
            # extract information
            L().log(604, pub_enc_alg, pub_enc_keylen, size_to_enc)
            algorithm = EnumTrafor().to_value(pub_enc_alg)
            key_len = EnumTrafor().to_value(pub_enc_keylen)
            
            # read Database
            if pub_enc_alg == AsymAuthMechEnum.ECC: 
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_reg_msg_inner_enc'], mode='ENCRYPTION', param_len=key_len, alg=algorithm, data_size=size_to_enc, description='t_reg_msg_inner_enc')
            else: 
                if size_to_enc > ((float(key_len) / 8) - 11): 
                    size_to_enc_in = ceil((float(key_len) / 8) - 11)
                else:
                    size_to_enc_in = size_to_enc
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_reg_msg_inner_enc'], exp=pub_enc_alg_option, mode='ENCRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_enc_in, description='t_reg_msg_inner_enc')
                
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(size_to_enc / ((float(key_len) / 8) - 11))
                db_val = db_val * nr_chuncks
                
            # return result
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_reg_msg_inner_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_reg_msg_inner_enc'], size_to_enc, pub_enc_alg, pub_enc_keylen, pub_enc_alg_option]))
                L().log(603, 't_reg_msg_inner_enc')
        
            return 0.001  # self.settings['t_reg_msg_inner_enc'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_INNER'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_reg_msg_inner_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_reg_msg_inner_enc'], size_to_enc, pub_enc_alg, pub_enc_keylen, pub_enc_alg_option]))
            return 0.000000001
    
    
    def c_t_reg_msg_hash(self, size_to_hash, hash_mech):

        try:
            # extract infos
            L().log(605, hash_mech, size_to_hash)
            algorithm = EnumTrafor().to_value(hash_mech)
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_reg_msg_hash'], mode='HASH', alg=algorithm, data_size=size_to_hash, description='t_reg_msg_hash')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_reg_msg_hash' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_reg_msg_hash'], size_to_hash, hash_mech]))
                L().log(603, 't_reg_msg_hash')
            return 0.01  # self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_reg_msg_hash' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_reg_msg_hash'], size_to_hash, hash_mech]))
            return 0.000000001
        
    
    def c_t_reg_msg_outter_enc(self, size_to_enc, pub_enc_alg, pub_enc_keylen, pub_enc_alg_option):
        ''' time to encrypt the outter part of the reg. msg. i.e. the hashed inner part
            -> sign procedure
        '''
        
        try:
            # extract infos
            L().log(606, pub_enc_alg, pub_enc_keylen, size_to_enc)
            algorithm = EnumTrafor().to_value(pub_enc_alg)
            key_len = EnumTrafor().to_value(pub_enc_keylen) 
            
            # DB Lookup
            if pub_enc_alg == AsymAuthMechEnum.ECC: 
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_reg_msg_outter_enc'], mode='SIGN', param_len=key_len, alg=algorithm, data_size=size_to_enc, description='t_reg_msg_outter_enc')
            if pub_enc_alg == AsymAuthMechEnum.RSA and self.library_tags['t_reg_msg_outter_enc'] == "CyaSSL": 
                if size_to_enc > (float(key_len) / 8): 
                    size_to_enc_in = ceil(float(key_len) / 8)
                else:
                    size_to_enc_in = size_to_enc
                
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_reg_msg_outter_enc'], mode='DECRYPTION', exp=pub_enc_alg_option, keylen=key_len, alg=algorithm, data_size=size_to_enc_in, description='t_reg_msg_outter_enc')
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(size_to_enc / (float(key_len) / 8))
                db_val = db_val * nr_chuncks
                
            if pub_enc_alg == AsymAuthMechEnum.RSA and self.library_tags['t_reg_msg_outter_enc'] in ["Crypto_Lib_SW", "Crypto_Lib_HW"]: 
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_reg_msg_outter_enc'], mode='SIGN', exp=pub_enc_alg_option, keylen=key_len, alg=algorithm, data_size=size_to_enc, description='t_reg_msg_outter_enc')
                
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_reg_msg_outter_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_reg_msg_outter_enc'], size_to_enc, pub_enc_alg, pub_enc_keylen, pub_enc_alg_option]))
                L().log(603, 't_reg_msg_outter_enc')
            return 0.01  # self.settings['t_reg_msg_outter_enc'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_OUTTER'
       
        except:
            logging.warn("Error: Could not find in DB the Value in 't_reg_msg_outter_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_reg_msg_outter_enc'], size_to_enc, pub_enc_alg, pub_enc_keylen, pub_enc_alg_option]))
            return 0.000000001
       
        
    def c_t_conf_msg_dec_time(self, sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode):
        ''' time to decrypt the confirmation message'''
        
        try:
            # extract infos
            L().log(607, 't_conf_msg_dec_time', sym_dec_alg, sym_dec_keylen, size_to_dec)
            algorithm = EnumTrafor().to_value(sym_dec_alg)
            algorithm_mode = EnumTrafor().to_value(sym_dec_alg_mode)
            key_len = EnumTrafor().to_value(sym_dec_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_conf_msg_dec_time'], alg_mode=algorithm_mode, mode='DECRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_dec, description='t_conf_msg_dec_time')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_conf_msg_dec_time' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_conf_msg_dec_time'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode]))
                L().log(603, 't_conf_msg_dec_time')
            
            return 0.01  # self.settings['t_conf_msg_dec_time'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_DEC_CONF_MSG'      
        except:
            logging.warn("Error: Could not find in DB the Value in 't_conf_msg_dec_time' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_conf_msg_dec_time'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode]))
            return 0.000000001

    
    def c_t_req_msg_stream_enc(self, size_to_enc, sym_enc_alg, sym_enc_keylen, sym_enc_alg_option):
        ''' time to encrypt the request message'''
        try:
            # extract infos
            L().log(608, sym_enc_alg, sym_enc_keylen, size_to_enc)
            algorithm = EnumTrafor().to_value(sym_enc_alg)
            algorithm_mode = EnumTrafor().to_value(sym_enc_alg_option)
            key_len = EnumTrafor().to_value(sym_enc_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_req_msg_stream_enc'], alg_mode=algorithm_mode, mode='ENCRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_enc, description='t_req_msg_stream_enc')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_req_msg_stream_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_req_msg_stream_enc'], size_to_enc, sym_enc_alg, sym_enc_keylen, sym_enc_alg_option]))
                L().log(603, 't_req_msg_stream_enc')        
            return 0.01  # self.settings['t_req_msg_stream_enc'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_ENC_REQ_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_req_msg_stream_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_req_msg_stream_enc'], size_to_enc, sym_enc_alg, sym_enc_keylen, sym_enc_alg_option]))
            return 0.000000001
    
    
    def c_t_deny_msg_stream_dec(self, sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode): 
        ''' time to decrypt a msg stream '''
        try:
            # extract infos
            L().log(607, 't_deny_msg_stream_dec', sym_dec_alg, sym_dec_keylen, size_to_dec)
            algorithm = EnumTrafor().to_value(sym_dec_alg)
            alg_modee = EnumTrafor().to_value(sym_dec_alg_mode)
            key_len = EnumTrafor().to_value(sym_dec_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(alg_mode=alg_modee, lib=self.library_tags['t_deny_msg_stream_dec'], mode='DECRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_dec, description='t_deny_msg_stream_dec')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_deny_msg_stream_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_deny_msg_stream_dec'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode]))
                L().log(603, 't_deny_msg_stream_dec')              
            return 0.01  # self.settings['t_deny_msg_stream_dec'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_DEC_DENY_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_deny_msg_stream_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_deny_msg_stream_dec'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode]))
            return 0.000000001
    
    
    def c_t_grant_msg_stream_dec(self, sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode):
        ''' time to decrypt the grant message '''
        try:
            # extract infos
            L().log(610, 't_grant_msg_stream_dec', sym_dec_alg, sym_dec_keylen, size_to_dec)
            algorithm = EnumTrafor().to_value(sym_dec_alg)
            key_len = EnumTrafor().to_value(sym_dec_keylen) 
            alg_modee = EnumTrafor().to_value(sym_dec_alg_mode)
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(alg_mode=alg_modee, lib=self.library_tags['t_grant_msg_stream_dec'], mode='DECRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_dec, description='t_grant_msg_stream_dec')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_grant_msg_stream_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_grant_msg_stream_dec'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode]))
                L().log(603, 't_grant_msg_stream_dec')
            return 0.01  # self.settings['t_grant_msg_stream_dec'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_DEC_GRANT_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_grant_msg_stream_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_grant_msg_stream_dec'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode]))
            return 0.000000001

    
    def c_t_normal_msg_dec(self, sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode=False):
        ''' time to decrypt a normal message '''
        try:
            # extract infos
            L().log(610, 't_normal_msg_dec', sym_dec_alg, sym_dec_keylen, size_to_dec)        
            algorithm = EnumTrafor().to_value(sym_dec_alg)
            algorithm_mode = EnumTrafor().to_value(sym_dec_alg_mode)
            key_len = EnumTrafor().to_value(sym_dec_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_normal_msg_dec'], alg_mode=algorithm_mode, mode='DECRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_dec, description='t_normal_msg_dec')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val) 
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_normal_msg_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_normal_msg_dec'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode]))
                L().log(603, 't_normal_msg_dec')
            return 0.01  # self.settings['t_normal_msg_dec'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_normal_msg_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_normal_msg_dec'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_mode]))
            return 0.000000001
        
    
    def c_t_normal_msg_enc(self, sym_enc_alg, sym_enc_keylen, size_to_enc, sym_enc_alg_mode=False):
        ''' time to encrypt a normal message'''
        try:
            # extract infos
            L().log(607, 't_normal_msg_enc', sym_enc_alg, sym_enc_keylen, size_to_enc)
            algorithm_mode = EnumTrafor().to_value(sym_enc_alg_mode)
            algorithm = EnumTrafor().to_value(sym_enc_alg)
            key_len = EnumTrafor().to_value(sym_enc_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_normal_msg_enc'], alg_mode=algorithm_mode, mode='ENCRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_enc, description='t_normal_msg_enc')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val) 
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_normal_msg_enc' use 0.0...01\nUsed input: %s" % str([ self.library_tags['t_normal_msg_enc'], sym_enc_alg, sym_enc_keylen, size_to_enc, sym_enc_alg_mode]))
                L().log(603, 't_normal_msg_enc')
            return 0.01  # self.settings['t_normal_msg_enc'] = 'ecuSW.comm_mod.authorizer.SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_normal_msg_enc' use 0.0...01\nUsed input: %s" % str([ self.library_tags['t_normal_msg_enc'], sym_enc_alg, sym_enc_keylen, size_to_enc, sym_enc_alg_mode]))
            return 0.000000001

