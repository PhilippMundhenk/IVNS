import logging
from components.base.ecu.types.impl_ecu_simple import SimpleECU
from components.base.ecu.software.ecu_software import ECUSoftware
from components.security.ecu.software.impl_app_layer_sec_module import StdSecurityModuleAppLayer
from components.security.ecu.software.impl_comm_mod_sec_module import SecModStdCommModule
import config.project_registration as proj
from config.timing_db_admin import TimingDBMap
from enums.sec_cfg_enum import AsymAuthMechEnum, EnumTrafor
from tools.ecu_logging import ECULogger as L
from tools.general import General as G
import math
from math import ceil

class SecLwAuthSecurityModule(SimpleECU):
    ''' 
    This class implements the Security Module proposed in the
    Paper "Lightweight Authentication for Secure Automotive Networks"
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
        
        # no instantiation
        if sim_env == None: return  
        
        # software
        SimpleECU.__init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer)
        self._SECMODULE = True
        self.ecuSW = ECUSoftware(sim_env, SecModStdCommModule(sim_env), StdSecurityModuleAppLayer(sim_env, ecu_id=ecu_id))
        
        # connect 
        self._connect_hw_sw()
        
        # project settings
        self.SECMOD_CERT_HASHING_MECH = proj.SECMOD_CERT_HASHING_MECH 
        self.SECMOD_CERT_ENCRYPTION_MECH = proj.SECMOD_CERT_ENCRYPTION_MECH
        self.SECMOD_CERT_ENCRYPTION_MECH_OPTION = proj.SECMOD_CERT_ENCRYPTION_MECH_OPTION
        self.SECMOD_CERT_KEYL = proj.SECMOD_CERT_KEYL
        self.SECMOD_CERT_CA_LEN = proj.SECMOD_CERT_CA_LEN
        self.SECMOD_CERT_SIZE_HASH_TO_SIGN = proj.SECMOD_CERT_SIZE_HASH_TO_SIGN
        self.SECMOD_CERT_SIZE_HASH_SIGNED = proj.SECMOD_CERT_SIZE_HASH_SIGNED        
        
    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
                
        #===============================================================
        #     Sending Sizes
        #===============================================================        
        # Sending size of ECU Advertisement SSMA_SECM_CERT_SIZE
        self.settings['p_sec_mod_conf_msg_sending_size'] = 'ecuSW.app_lay.ecu_auth.SSMA_SECM_CONF_MSG_SIZE'  # same as SCCM_ECU_CONF_MSG_CIPHER_SIZE
        self.settings['p_str_auth_deny_msg_sending_size'] = 'ecuSW.app_lay.stream_auth.SSMA_SECM_DENY_MSG_SIZE'  # same as SSMA_GRANT_MSG_CIPHER_SIZE
        self.settings['p_str_auth_grant_msg_sending_size'] = 'ecuSW.app_lay.stream_auth.SSMA_SECM_GRANT_MSG_SIZE'  # same as SSMA_GRANT_MSG_CIPHER_SIZE
        self.settings['p_sec_mod_cert_size'] = 'ecuSW.app_lay.ecu_auth.SSMA_SECM_CERT_SIZE'     

        #=======================================================================
        #     Certification
        #=======================================================================
        self.settings['p_sec_mod_cert_hashing_mech'] = 'SECMOD_CERT_HASHING_MECH'
        self.settings['p_sec_mod_cert_enc_mech'] = 'SECMOD_CERT_ENCRYPTION_MECH'
        self.settings['p_sec_mod_cert_enc_mech_option'] = 'SECMOD_CERT_ENCRYPTION_MECH_OPTION'
        self.settings['p_sec_mod_cert_enc_keylen'] = 'SECMOD_CERT_KEYL'
        self.settings['p_sec_mod_cert_ca_len'] = 'SECMOD_CERT_CA_LEN'
        self.settings['p_sec_mod_cert_hash_size'] = 'SECMOD_CERT_SIZE_HASH_TO_SIGN'
        self.settings['p_sec_mod_cert_signed_hash_size'] = 'SECMOD_CERT_SIZE_HASH_SIGNED'
     
        self.settings['p_ecu_auth_cert_hash_mech'] = 'ecuSW.app_lay.ecu_auth.ECU_CERT_HASHING_MECH'
        self.settings['p_ecu_auth_cert_enc_mech'] = 'ecuSW.app_lay.ecu_auth.ECU_CERT_ENCRYPTION_MECH'
        self.settings['p_ecu_auth_cert_enc_mech_option'] = 'ecuSW.app_lay.ecu_auth.ECU_CERT_ENCRYPTION_MECH_OPTION'
        self.settings['p_ecu_auth_cert_enc_keylen'] = 'ecuSW.app_lay.ecu_auth.ECU_CERT_KEYL'
        self.settings['p_ecu_auth_cert_ca_len'] = 'ecuSW.app_lay.ecu_auth.ECU_CERT_CA_LEN'
        self.settings['p_ecu_auth_cert_hash_unsigned_size'] = 'ecuSW.app_lay.ecu_auth.ECU_CERT_SIZE_HASH_TO_SIGN'
        self.settings['p_ecu_auth_cert_hash_signed_size'] = 'ecuSW.app_lay.ecu_auth.ECU_CERT_SIZE_HASH'
                   
        #===============================================================================
        #  ECU Authentication
        #===============================================================================
        # Trigger Timings
        self.settings['t_ecu_auth_trigger_process'] = 'ecuSW.app_lay.ecu_auth.SSMA_TRIGGER_AUTH_PROCESS_T'
        self.settings['t_ecu_auth_trigger_intervall'] = 'ecuSW.app_lay.SSMA_ECU_AUTH_INTERVAL'   

        # Process registration message
        self.settings['t_ecu_auth_reg_msg_validate_cert'] = 'ecuSW.app_lay.ecu_auth.SSMA_VALID_CERT_REG_MSG'        
        self.settings['t_ecu_auth_reg_msg_create_comp_hash'] = 'ecuSW.app_lay.ecu_auth.SSMA_CREATE_CMP_HASH_REG_MSG'
        self.settings['t_ecu_auth_reg_msg_comp_hash_process'] = 'ecuSW.app_lay.ecu_auth.SSMA_HASH_CMPR_REG_MSG'  
        self.settings['t_ecu_auth_reg_msg_inner_dec'] = 'ecuSW.app_lay.ecu_auth.SSMA_DECR_INNER_REG_MSG'
        self.settings['t_ecu_auth_reg_msg_outter_dec'] = 'ecuSW.app_lay.ecu_auth.SSMA_DECR_OUTTER_REG_MSG'   
        
        self.settings['p_reg_msg_hash_alg'] = 'ecuSW.app_lay.ecu_auth.SCCM_ECU_REG_MSG_HASH'
        self.settings['p_reg_msg_inner_enc_method'] = 'ecuSW.app_lay.public_enc_algorithm'  # this is SSMA_SECM_PUB_ENC_ALG
        self.settings['p_reg_msg_inner_enc_method_option'] = 'ecuSW.app_lay.public_enc_algorithm_option'  # this is SSMA_SECM_PUB_ENC_ALG_OPTION
        
        self.settings['p_reg_msg_inner_enc_keylen'] = 'ecuSW.app_lay.public_enc_keylength'  # this is SSMA_SECM_PUB_ENC_KEY_LEN
        self.settings['p_reg_msg_inner_cipher_size'] = 'ecuSW.app_lay.ecu_auth.SSMA_REG_MSG_CIPHER_SIZE_INNER'
        self.settings['p_reg_msg_outter_cipher_size'] = 'ecuSW.app_lay.ecu_auth.SSMA_REG_MSG_CIPHER_SIZE_OUTER'
        self.settings['p_reg_msg_outter_hash_size'] = 'ecuSW.app_lay.ecu_auth.SCCM_ECU_REG_MSG_HASH_LEN'
        self.settings['p_reg_msg_inner_content_size'] = 'ecuSW.app_lay.ecu_auth.SSMA_REG_MSG_CT_SIZE_INNER'
        self.settings['p_reg_msg_outter_enc_alg'] = 'ecuSW.app_lay.ecu_auth.SCCM_ECU_PUB_ENC_ALG'
        self.settings['p_reg_msg_outter_enc_alg_option'] = 'ecuSW.app_lay.ecu_auth.SCCM_ECU_PUB_ENC_ALG_OPTION'
        self.settings['p_reg_msg_outter_enc_keylen'] = 'ecuSW.app_lay.ecu_auth.SCCM_ECU_PUB_ENC_KEY_LEN'

        # Process confirmation message
        self.settings['t_ecu_auth_conf_msg_enc'] = 'ecuSW.app_lay.ecu_auth.SSMA_ENCR_CONF_MSG_ECU_KEY'   
                
        self.settings['p_ecu_auth_conf_msg_size'] = 'ecuSW.app_lay.ecu_auth.SCCM_ECU_CONF_MSG_SIZE'  # before encryption    
        
        #=======================================================================
        #  Stream Authorization
        #=======================================================================    
        
        # Process request message
        self.settings['t_str_auth_decr_req_msg'] = 'ecuSW.app_lay.stream_auth.SSMA_STREAM_REQ_INI_DECR'
        
        self.settings['p_req_msg_content_size'] = 'ecuSW.app_lay.stream_auth.SSMA_SIZE_REQ_MSG_CONTENT'
        self.settings['p_req_msg_cipher_size'] = 'ecuSW.app_lay.stream_auth.SSMA_SIZE_REQ_MSG_CIPHER'
        
        # Process deny message
        self.settings['t_str_auth_enc_deny_msg'] = 'ecuSW.app_lay.stream_auth.SSMA_STREAM_ENC_DENY_MSG'
        
        # Process grant message
        self.settings['t_str_auth_keygen_grant_msg'] = 'ecuSW.app_lay.stream_auth.SSMA_SESS_KEYGEN_GRANT_MSG'        
        self.settings['t_str_auth_enc_grant_msg'] = 'ecuSW.app_lay.stream_auth.SSMA_STREAM_ENC_GRANT_MSG'  
             
        self.settings['p_grant_msg_content_size'] = 'ecuSW.app_lay.stream_auth.SSMA_GRANT_MSG_CT_SIZE'
        
        self.settings['p_str_auth_ses_key_enc_alg'] = 'ecuSW.app_lay.stream_auth.SSMA_SECM_SES_KEY_ENC_ALG'
        self.settings['p_str_auth_ses_key_enc_alg_mode'] = 'ecuSW.app_lay.stream_auth.SSMA_SECM_SES_KEY_ENC_ALG_MODE'
        self.settings['p_str_auth_ses_key_enc_keylen'] = 'ecuSW.app_lay.stream_auth.SSMA_SECM_SES_KEY_ENC_KEY_LEN'     
        self.settings['p_str_auth_ses_key_validity'] = 'ecuSW.app_lay.stream_auth.SSMA_SECM_SES_KEY_VALIDITY'        
     
    
    def register_ecu(self, ecu):       
        ''' each ECU that can be authenticated and is allowed to send streams
            on the CAN bus has to register with this security module
        
            Input:    ecu    AbstractECU    ECU that will be registered with this security module
            Output:   -    
        ''' 
        self.ecuSW.app_lay.register_ecu(ecu)
        
    
    def register_ecus(self, ecu_list):
        ''' each ECU that can be authenticated and is allowed to send streams
            on the CAN bus has to register with this security module
        
            Input:    ecu_list    list    list of AbstractECUs that will be registered with this security module
            Output:   -    
        ''' 
        self.ecuSW.app_lay.register_ecus(ecu_list)
        
    
    def set_security_set_from_rm(self, certificate_manager):
        ''' as certification constellations can be predefined in the
            certificate manager object this method can be used to set
            the ECUs configuration from this object. Thereby the ECUs
            certificate and all root certificates that this ECU has are 
            set
            
            Input:  certificate_manager    CertificateManager     manager object that has a predefined certificate constellation
            Output: -
        '''
        try:
            root_certs = certificate_manager.sec_mod_root_cert[self.ecu_id]    
            self.ecuSW.app_lay.ecu_auth.lst_root_certificates = root_certs
        except:
            pass
 
        try:            
            cert = certificate_manager.sec_cert[self.ecu_id]
            self.ecuSW.app_lay.sec_mod_certificat = cert
            self.ecuSW.app_lay.ecu_auth.certificate = cert
        except:            
            L().log_err(100, self.ecu_id)
    
    
    def get_allowed_streams(self):
        ''' returns all MessageStream objects that were added to this
            security module so far
        
            Input:     -
            Output:    streams        list    list of MessageStreams 
        '''
        return self.ecuSW.app_lay.stream_auth.allowed_streams
        
    
    def set_allowed_streams(self, streams_list):
        ''' sets a list of MessageStream objects that define the streams
            that are allowed to be send during this simulation.
            
            Input:    streams_list        list        list of MessageStream objects
            Output:   -
        '''
        self.ecuSW.app_lay.stream_auth.set_allowed_streams(streams_list)

    
    def get_type_id(self):
        ''' returns the id of this ECU type
        
            Input:    -
            Output:   ecu_type    string    type of this ECU; e.g.'TLSECU'
        '''
        return "Sec_Mod_LW_Auth"
    
    @property
    
    def ecu_id(self):
        return self._ecu_id

    @ecu_id.setter
    
    def ecu_id(self, value):
        self.ecuSW.app_lay.ecu_id = value     
        self._ecu_id = value    

    
    def monitor_update(self):
        ''' returns a list of monitor inputs
            
            Input:    -
            Output:   list    list    list of MonitorInput objects
        '''
        return self.ecuSW.app_lay.monitor_update()

class StdSecurLwSecModTimingFunctions(object):    
    '''
    If used this class sets the timing behaviour
    
    Looks up values in the measurements.db
    if no value is found tries to interpolate it from neighbours
    
    '''

    def __init__(self, main_library_tag='CyaSSL'):
        ''' Constructor
            
            Input:  main_library_tag    string      tag of the library that will be used for     
                                                    access of the timing values per default
            Output: -
        '''
        # tags
        self.available_tags = ['CyaSSL', 'Crypto_Lib_HW', 'Crypto_Lib_SW']
        self.library_tag = main_library_tag

        # function map
        self.function_map = {}
        self.function_map['t_ecu_auth_reg_msg_validate_cert'] = self.c_t_ecu_auth_reg_msg_validate_cert
        self.function_map['t_ecu_auth_reg_msg_create_comp_hash'] = self.c_t_ecu_auth_reg_msg_create_comp_hash    
        self.function_map['t_ecu_auth_reg_msg_inner_dec'] = self.c_t_ecu_auth_reg_msg_inner_dec
        self.function_map['t_ecu_auth_reg_msg_outter_dec'] = self.c_t_ecu_auth_reg_msg_outter_dec
        self.function_map['t_ecu_auth_conf_msg_enc'] = self.c_t_ecu_auth_conf_msg_enc
        self.function_map['t_str_auth_decr_req_msg'] = self.c_t_str_auth_decr_req_msg
        self.function_map['t_str_auth_enc_deny_msg'] = self.c_t_str_auth_enc_deny_msg
        self.function_map['t_str_auth_keygen_grant_msg'] = self.c_t_str_auth_keygen_grant_msg
        self.function_map['t_str_auth_enc_grant_msg'] = self.c_t_str_auth_enc_grant_msg

        # library tag per setting
        self.library_tags = {}
        self.library_tags['t_ecu_auth_reg_msg_validate_cert'] = self.library_tag
        self.library_tags['t_ecu_auth_reg_msg_create_comp_hash'] = self.library_tag  
        self.library_tags['t_ecu_auth_reg_msg_inner_dec'] = self.library_tag
        self.library_tags['t_ecu_auth_reg_msg_outter_dec'] = self.library_tag
        self.library_tags['t_ecu_auth_conf_msg_enc'] = self.library_tag
        self.library_tags['t_str_auth_decr_req_msg'] = self.library_tag
        self.library_tags['t_str_auth_enc_deny_msg'] = self.library_tag
        self.library_tags['t_str_auth_keygen_grant_msg'] = self.library_tag
        self.library_tags['t_str_auth_enc_grant_msg'] = self.library_tag

    
    def get_function_map(self):
        ''' returns the function_map that maps the timing parameters to 
            functions that are called when the timing parameters are accessed
            

            Input:    -
            Output:   function_map    dictionary        maps timing parameters to functions. 
                                                        Key:     settings identifier
                                                        Value:   method called for this setting 
        '''
        return self.function_map

    
    def c_t_ecu_auth_reg_msg_validate_cert(self, cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn, cert_size):
        ''' time to validate the ecus certificate, hash to sign is the size of the Certificate to be signed '''
        try:
            # extract infos
            L().log(700, cert_enc_mech, cert_enc_keylen, cert_size_hashtosign, cert_ca_len)
            db_val = False
            algorithm = EnumTrafor().to_value(cert_enc_mech)
            hash_alg = EnumTrafor().to_value(cert_hash_mech)
            key_len = EnumTrafor().to_value(cert_enc_keylen) 
        
            # CrypLi RSA: Verify = Time of hash creation + time to encrypt hash / CyaSSL & CrypLi ECC: Verify operation
            if cert_enc_mech == AsymAuthMechEnum.ECC:  
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_validate_cert'], mode='VERIFY', \
                                                       param_len=key_len, alg=algorithm, data_size=cert_size_hashtosign, description='t_ecu_auth_reg_msg_validate_cert')                
            
            if self.library_tags['t_ecu_auth_reg_msg_validate_cert'] in ["Crypto_Lib_SW", "Crypto_Lib_HW"] and cert_enc_mech == AsymAuthMechEnum.RSA:  # RSA SIGN = DECRYPTION, VERIFY= ENCRYPTION
                # 1. create hash of certificate content
                db_val_1 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_validate_cert'], mode='HASH', alg=hash_alg, data_size=cert_size, description='t_ecu_auth_reg_msg_validate_cert')
                
                # 2. decrypt digital signature (signed hash size) using public key of certificate (public key operation -> similar to public encrypt)
                if cert_size_hashsigned > ((float(key_len) / 8) - 11): 
                    cert_size_hashsigned_in = ceil((float(key_len) / 8) - 11)
                else:
                    cert_size_hashsigned_in = cert_size_hashsigned
                db_val_2 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_validate_cert'], mode='VERIFY', keylen=key_len, alg=algorithm, data_size=cert_size_hashsigned_in, exp=cert_alg_optn, description='t_ecu_auth_reg_msg_validate_cert')     
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(cert_size_hashsigned / ((float(key_len) / 8) - 11))
                db_val_2 = db_val_2 * nr_chuncks
                
                # 3. create hash of digital signature                 
                db_val_3 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_validate_cert'], mode='HASH', alg=hash_alg, data_size=cert_size_hashtosign, description='t_ecu_auth_reg_msg_validate_cert')
                
                db_val = db_val_1 + db_val_2 + db_val_3
                
    
            if self.library_tags['t_ecu_auth_reg_msg_validate_cert'] == "CyaSSL" and cert_enc_mech == AsymAuthMechEnum.RSA:  
                # 1. create hash of certificate content
                db_val_1 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_validate_cert'], mode='HASH', alg=hash_alg, data_size=cert_size, description='t_ecu_auth_reg_msg_validate_cert')
                
                # 2. decrypt digital signature (signed hash size) using public key of certificate (public key operation -> similar to public encrypt)
                if cert_size_hashsigned > ((float(key_len) / 8) - 11): 
                    cert_size_hashsigned_in = ceil((float(key_len) / 8) - 11)
                else:
                    cert_size_hashsigned_in = cert_size_hashsigned
                db_val_2 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_validate_cert'], mode='ENCRYPTION', keylen=key_len, alg=algorithm, data_size=cert_size_hashsigned_in, exp=cert_alg_optn, description='t_ecu_auth_reg_msg_validate_cert')     
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(cert_size_hashsigned / ((float(key_len) / 8) - 11))
                db_val_2 = db_val_2 * nr_chuncks
                
                # 3. create hash of digital signature                 
                db_val_3 = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_validate_cert'], mode='HASH', alg=hash_alg, data_size=cert_size_hashtosign, description='t_ecu_auth_reg_msg_validate_cert')
                
                db_val = db_val_1 + db_val_2 + db_val_3
    
            # return value
            if db_val: 
                L().log(602, db_val)           
            else:
                logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_reg_msg_validate_cert' use 0.0...01\nUsed input: %s" % str([ self.library_tags['t_ecu_auth_reg_msg_validate_cert'], cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn]))
                L().log(603, 't_ecu_auth_reg_msg_validate_cert')
                return 0.0000000001 
            abs_time = cert_ca_len * db_val  # repeat cert_ca_len times        
            return abs_time  # self.settings['t_ecu_auth_reg_msg_validate_cert'] = 'ecuSW.app_lay.ecu_auth.SSMA_VALID_CERT_REG_MSG'       
        except:
            logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_reg_msg_validate_cert' use 0.0...01\nUsed input: %s" % str([ self.library_tags['t_ecu_auth_reg_msg_validate_cert'], cert_hash_mech, cert_enc_mech, cert_enc_keylen, \
                                   cert_ca_len, cert_size_hashtosign, cert_size_hashsigned, cert_alg_optn]))
            return 0.000000001

            
    def c_t_ecu_auth_reg_msg_create_comp_hash(self, size_to_hash, hash_mech):
        ''' time it takes to create the hash for the comparision in the registration message '''
        try:
            # extract infos
            L().log(605, hash_mech, size_to_hash)
            algorithm = EnumTrafor().to_value(hash_mech)
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_create_comp_hash'], mode='HASH', alg=algorithm, data_size=size_to_hash, description='t_ecu_auth_reg_msg_create_comp_hash')
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_reg_msg_create_comp_hash' use 0.0...01\nUsed input: %s" % str([ self.library_tags['t_ecu_auth_reg_msg_create_comp_hash'], size_to_hash, hash_mech]))
                L().log(603, 't_reg_msg_hash')
            return 0.01
        except:
            logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_reg_msg_create_comp_hash' use 0.0...01\nUsed input: %s" % str([ self.library_tags['t_ecu_auth_reg_msg_create_comp_hash'], size_to_hash, hash_mech]))
            return 0.000000001

    
    def c_t_ecu_auth_reg_msg_inner_dec(self, pub_dec_alg, pub_dec_keylen, size_to_dec, pub_dec_alg_option):
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
                db_val = TimingDBMap().lookup_interpol(exp=al_mode, lib=self.library_tags['t_ecu_auth_reg_msg_inner_dec'], mode='DECRYPTION', \
                                                       param_len=key_len, alg=algorithm, data_size=size_to_dec, description='t_ecu_auth_reg_msg_inner_dec')
            else: 
                db_val = TimingDBMap().lookup_interpol(exp=al_mode, lib=self.library_tags['t_ecu_auth_reg_msg_inner_dec'], mode='DECRYPTION', \
                                                       keylen=key_len, alg=algorithm, data_size=size_to_dec, description='t_ecu_auth_reg_msg_inner_dec')
            
            # return result
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_reg_msg_inner_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_ecu_auth_reg_msg_inner_dec'], pub_dec_alg, pub_dec_keylen, size_to_dec, pub_dec_alg_option]))
                L().log(603, 't_ecu_auth_reg_msg_inner_dec')
    
            return 0.01  # self.settings['t_ecu_auth_reg_msg_inner_dec'] = 'ecuSW.app_lay.ecu_auth.SSMA_DECR_INNER_REG_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_reg_msg_inner_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_ecu_auth_reg_msg_inner_dec'], pub_dec_alg, pub_dec_keylen, size_to_dec, pub_dec_alg_option]))
            return 0.000000001
    
    
    def c_t_ecu_auth_reg_msg_outter_dec(self, pub_dec_alg, pub_dec_keylen, size_to_dec, pub_dec_alg_option):
        ''' time to decrypt the outter registration message 
            -> Verify == Public Decrypt!  '''
        try:
            # extract infos
            L().log(702, pub_dec_alg, pub_dec_keylen, size_to_dec)
            algorithm = EnumTrafor().to_value(pub_dec_alg)
            alg_opt = EnumTrafor().to_value(pub_dec_alg_option)
            key_len = EnumTrafor().to_value(pub_dec_keylen) 
            
            # DB Lookup        
            if pub_dec_alg == AsymAuthMechEnum.ECC:
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_outter_dec'], mode='VERIFY', param_len=key_len, \
                                                       alg=algorithm, data_size=size_to_dec, description='t_ecu_auth_reg_msg_outter_dec')
            if pub_dec_alg == AsymAuthMechEnum.RSA and self.library_tags['t_ecu_auth_reg_msg_outter_dec'] == "CyaSSL":
                if size_to_dec > ((float(key_len) / 8) - 11): 
                    size_to_dec_in = ceil((float(key_len) / 8) - 11)
                else:
                    size_to_dec_in = size_to_dec
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_outter_dec'], exp=alg_opt, mode='ENCRYPTION', \
                                                       keylen=key_len, alg=algorithm, data_size=size_to_dec_in, description='t_ecu_auth_reg_msg_outter_dec')
                # in case of RSA have to slice the message and encrypt each of those
                nr_chuncks = math.ceil(size_to_dec / ((float(key_len) / 8) - 11))
                db_val = db_val * nr_chuncks
            if pub_dec_alg == AsymAuthMechEnum.RSA and self.library_tags['t_ecu_auth_reg_msg_outter_dec'] in ["Crypto_Lib_SW", "Crypto_Lib_HW"]:
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_ecu_auth_reg_msg_outter_dec'], exp=alg_opt, mode='VERIFY', \
                                                       keylen=key_len, alg=algorithm, data_size=size_to_dec, description='t_ecu_auth_reg_msg_outter_dec')
    
            # return result
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_reg_msg_outter_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_ecu_auth_reg_msg_outter_dec'], pub_dec_alg, pub_dec_keylen, size_to_dec, pub_dec_alg_option]))
                L().log(603, 't_ecu_auth_reg_msg_outter_dec')            
            return 0.01  # self.settings['t_ecu_auth_reg_msg_outter_dec'] = 'ecuSW.app_lay.ecu_auth.SSMA_DECR_OUTTER_REG_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_reg_msg_outter_dec' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_ecu_auth_reg_msg_outter_dec'], pub_dec_alg, pub_dec_keylen, size_to_dec, pub_dec_alg_option]))
            return 0.000000001

    
    def c_t_ecu_auth_conf_msg_enc(self, size_to_enc, sym_enc_alg, sym_enc_keylen, sym_enc_alg_mode):
        ''' time to encrypt the conf. msg with the ecu key'''
        try:
            # extract infos
            L().log(703, sym_enc_alg, sym_enc_keylen, size_to_enc)        
            algorithm = EnumTrafor().to_value(sym_enc_alg)
            algo_mode = EnumTrafor().to_value(sym_enc_alg_mode)
            key_len = EnumTrafor().to_value(sym_enc_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(alg_mode=algo_mode, lib=self.library_tags['t_ecu_auth_conf_msg_enc'], mode='ENCRYPTION', \
                                                   keylen=key_len, alg=algorithm, data_size=size_to_enc, description='t_ecu_auth_conf_msg_enc')
            
            # return result
            if db_val:
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_conf_msg_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_ecu_auth_conf_msg_enc'], size_to_enc, sym_enc_alg, sym_enc_keylen, sym_enc_alg_mode]))
                L().log(603, 't_ecu_auth_conf_msg_enc')        
            return 0.01  # self.settings['t_ecu_auth_reg_msg_outter_dec'] = 'ecuSW.app_lay.ecu_auth.SSMA_DECR_OUTTER_REG_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_ecu_auth_conf_msg_enc' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_ecu_auth_conf_msg_enc'], size_to_enc, sym_enc_alg, sym_enc_keylen, sym_enc_alg_mode]))
            return 0.000000001
    
    
    def c_t_str_auth_decr_req_msg(self, sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_option):
        ''' time to decrypt the request message with the ecu key'''
        try:
            # extract infos
            L().log(704, sym_dec_alg, sym_dec_keylen, size_to_dec)        
            algorithm = EnumTrafor().to_value(sym_dec_alg)
            alg_option = EnumTrafor().to_value(sym_dec_alg_option)
            key_len = EnumTrafor().to_value(sym_dec_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(alg_mode=alg_option, lib=self.library_tags['t_str_auth_decr_req_msg'], mode='DECRYPTION', \
                                                    keylen=key_len, alg=algorithm, data_size=size_to_dec, description='t_str_auth_decr_req_msg')
            
            # return values
            if db_val:
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_str_auth_decr_req_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_str_auth_decr_req_msg'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_option]))
                L().log(603, 't_str_auth_decr_req_msg')
            
            return 0.01  # self.settings['t_str_auth_decr_req_msg'] = 'ecuSW.app_lay.stream_auth.SSMA_STREAM_REQ_INI_DECR'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_str_auth_decr_req_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_str_auth_decr_req_msg'], sym_dec_alg, sym_dec_keylen, size_to_dec, sym_dec_alg_option]))
            return 0.000000001
          
    
    def c_t_str_auth_enc_deny_msg(self, sym_enc_alg, sym_enc_keylen, size_to_enc, sym_enc_alg_mode): 
        ''' time to encrypt the deny message'''
        try:
            # extract infos
            L().log(705, sym_enc_alg, sym_enc_keylen, size_to_enc)
            algorithm = EnumTrafor().to_value(sym_enc_alg)
            algo_mode = EnumTrafor().to_value(sym_enc_alg_mode)
            key_len = EnumTrafor().to_value(sym_enc_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(alg_mode=algo_mode, lib=self.library_tags['t_str_auth_enc_deny_msg'], mode='ENCRYPTION', \
                                                   keylen=key_len, alg=algorithm, data_size=size_to_enc, description='t_str_auth_enc_deny_msg')
            
            # return values
            if db_val:
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_str_auth_enc_deny_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_str_auth_enc_deny_msg'], sym_enc_alg, sym_enc_keylen, size_to_enc, sym_enc_alg_mode]))
                L().log(603, 't_str_auth_enc_deny_msg')
            return 0.01  # self.settings['t_str_auth_enc_deny_msg'] = 'ecuSW.app_lay.stream_auth.SSMA_STREAM_ENC_DENY_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_str_auth_enc_deny_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_str_auth_enc_deny_msg'], sym_enc_alg, sym_enc_keylen, size_to_enc, sym_enc_alg_mode]))
            return 0.000000001
        
    
    def c_t_str_auth_enc_grant_msg(self, sym_enc_alg, sym_enc_keylen, size_to_enc, sym_enc_alg_mode):
        ''' time to encrypt the grant message'''
        try:
            # extract infos
            L().log(706, sym_enc_alg, sym_enc_keylen, size_to_enc)
            algorithm = EnumTrafor().to_value(sym_enc_alg)
            algo_mode = EnumTrafor().to_value(sym_enc_alg_mode)
            key_len = EnumTrafor().to_value(sym_enc_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(alg_mode=algo_mode, lib=self.library_tags['t_str_auth_enc_grant_msg'], mode='ENCRYPTION', \
                                                   keylen=key_len, alg=algorithm, data_size=size_to_enc, description='t_str_auth_enc_grant_msg')
            
            # return values
            if db_val:
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_str_auth_enc_grant_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_str_auth_enc_grant_msg'], sym_enc_alg, sym_enc_keylen, size_to_enc, sym_enc_alg_mode]))
                L().log(603, 't_str_auth_enc_grant_msg')        
            return 0.01  # self.settings['t_str_auth_enc_grant_msg'] = 'ecuSW.app_lay.stream_auth.SSMA_STREAM_ENC_GRANT_MSG'        
        except:
            logging.warn("Error: Could not find in DB the Value in 't_str_auth_enc_grant_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_str_auth_enc_grant_msg'], sym_enc_alg, sym_enc_keylen, size_to_enc, sym_enc_alg_mode]))
            return 0.000000001

    
    def c_t_str_auth_keygen_grant_msg(self, sym_enc_alg, sym_enc_keylen):
        ''' time to generate a session key '''
        try:
            # extract infos
            L().log(707, sym_enc_alg, sym_enc_keylen)
            algorithm = EnumTrafor().to_value(sym_enc_alg)
            key_len = EnumTrafor().to_value(sym_enc_keylen) 
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_str_auth_keygen_grant_msg'], mode='KEYGEN', keylen=key_len, alg=algorithm, description='t_str_auth_keygen_grant_msg')
            
            # return values
            if db_val:
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                logging.warn("Error: Could not find in DB the Value in 't_str_auth_keygen_grant_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_str_auth_keygen_grant_msg'], sym_enc_alg, sym_enc_keylen]))
                L().log(603, 't_str_auth_keygen_grant_msg')     
            return 0.01  # self.settings['t_str_auth_keygen_grant_msg'] = 'ecuSW.app_lay.stream_auth.SSMA_SESS_KEYGEN_GRANT_MSG'
        except:
            logging.warn("Error: Could not find in DB the Value in 't_str_auth_keygen_grant_msg' use 0.0...01\nUsed input: %s" % str([self.library_tags['t_str_auth_keygen_grant_msg'], sym_enc_alg, sym_enc_keylen]))
            return 0.000000001

