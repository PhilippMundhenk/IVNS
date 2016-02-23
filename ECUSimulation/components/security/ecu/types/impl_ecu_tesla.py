from components.base.ecu.software.ecu_software import ECUSoftware
from components.base.ecu.types.impl_ecu_simple import SimpleECU
from tools.ecu_logging import ECULogger as L
from components.security.ecu.software.impl_comm_module_tesla import TeslaCommModule
from components.security.ecu.software.impl_app_layer_tesla import TeslaApplicationLayer
from enums.sec_cfg_enum import EnumTrafor, SymAuthMechEnum, AuKeyLengthEnum, \
    AsymAuthMechEnum
from config.timing_db_admin import TimingDBMap
from tools.general import General as G
import logging
import math
from math import ceil
from config import can_registration


class TeslaECU(SimpleECU):
    '''
    this ECU enables secure communication using the TESLA protocol 
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
        # Set Settings
        self.set_settings()
        self._authenticated = False
        self._allowed_streams = can_registration.TESLA_MESSAGES
        
        # no instantiation
        if sim_env == None: return 
        
        # set SW and HW
        SimpleECU.__init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer)                
        self.ecuSW = ECUSoftware(sim_env, TeslaCommModule(sim_env, ecu_id), \
                                  TeslaApplicationLayer(sim_env, ecu_id))
        
        # connect 
        self._connect_hw_sw()                
        
    def set_max_message_number(self, nr_messages):
        ''' sets the number of messages that are sent by this ecu per
            stream
        
            Input:    nr_messages    int    number of messages sent
            Output:    -
        '''
        self.ecuSW.app_lay.set_max_message_number(nr_messages)
    
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
    
    
    def get_type_id(self):
        ''' returns the id of this ECU type
        
            Input:    -
            Output:   ecu_type    string    type of this ECU; e.g.'TLSECU'
        '''
        return "TeslaECU"
    
    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        self.settings['p_start_setup_time'] = 'ecuSW.app_lay.TESLA_SETUP_START_TIME'
        self.settings['p_repeat_setup_time'] = 'ecuSW.app_lay.TESLA_SETUP_INTERVAL_TIME'
        self.settings['p_key_chain_len'] = 'ecuSW.comm_mod.TESLA_KEY_CHAIN_LEN' 
        
        self.settings['p_mac_key_algorithm'] = 'ecuSW.comm_mod.TESLA_MAC_KEY_ALGORITHM' 
        self.settings['p_mac_key_len'] = 'ecuSW.comm_mod.TESLA_MAC_KEY_LEN' 
        
        self.settings['p_prf_key_chain_method'] = 'ecuSW.comm_mod.TESLA_PRF_KEY_CHAIN' 
        self.settings['p_prf_mac_key_method'] = 'ecuSW.comm_mod.TESLA_PRF_MAC_KEY' 
        
        self.settings['p_key_exchange_algorithm'] = 'ecuSW.comm_mod.TESLA_KEY_EXCHANGE_ENC_ALGORITHM' 
        self.settings['p_key_exchange_keylen'] = 'ecuSW.comm_mod.TESLA_KEY_EXCHANGE_KEY_LEN' 
        self.settings['p_key_exchange_algorithm_option'] = 'ecuSW.comm_mod.TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION' 
        
        self.settings['p_key_exchange_clear_size'] = 'ecuSW.comm_mod.TESLA_KEY_EXCHANGE_CLEAR_SIZE' 
        self.settings['p_key_exchange_cipher_size'] = 'ecuSW.comm_mod.TESLA_KEY_EXCHANGE_CIPHER_SIZE' 
        
        self.settings['p_legid_mac_key_algorithm'] = 'ecuSW.comm_mod.TESLA_KEY_LEGID_MAC_ALGORITHM' 
        self.settings['p_legid_mac_key_len'] = 'ecuSW.comm_mod.TESLA_KEY_LEGID_MAC_KEY_LEN' 
        
        self.settings['p_mac_transmit_size'] = 'ecuSW.comm_mod.TESLA_MAC_SIZE_TRANSMIT' 
        
        #=======================================================================
        #     Timings
        #=======================================================================
        self.settings['t_mac_key_generation_time'] = 'ecuSW.comm_mod.TESLA_ONE_KEY_CREATION' 
        self.settings['t_generate_compare_mac'] = 'ecuSW.comm_mod.TESLA_MAC_GEN_VERIFY_TIME_TRANSMIT' 
        self.settings['t_generate_mac'] = 'ecuSW.comm_mod.TESLA_MAC_GEN_TIME_TRANSMIT' 
        
        self.settings['t_key_exchange_encryption'] = 'ecuSW.comm_mod.TESLA_KEY_EXCHANGE_ENC_TIME' 
        self.settings['t_key_exchange_decryption'] = 'ecuSW.comm_mod.TESLA_KEY_EXCHANGE_DEC_TIME' 
        self.settings['t_prf_for_key_legitimation'] = 'ecuSW.comm_mod.TESLA_KEY_LEGID_PRF_TIME' 
                     
        return self.settings
        
    
    def monitor_update(self):
        ''' returns a list of monitor inputs
            
            Input:    -
            Output:   list    list    list of MonitorInput objects
        '''
        return self.ecuSW.comm_mod.monitor_update()

class StdTeslaECUTimingFunctions(object):
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
        self.available_tags = ['CyaSSL', 'Crypto_Lib_HW', 'Crypto_Lib_SW']

        self.library_tag = main_library_tag  # e.g. CyaSSL, or CryptoLib

        self.function_map = {}
        self.function_map['t_mac_key_generation_time'] = self.c_t_mac_key_generation_time
        self.function_map['t_generate_compare_mac'] = self.c_t_generate_compare_mac
        self.function_map['t_generate_mac'] = self.c_t_generate_mac        
        self.function_map['t_key_exchange_encryption'] = self.c_t_key_exchange_encryption
        self.function_map['t_key_exchange_decryption'] = self.c_t_key_exchange_decryption
        self.function_map['t_prf_for_key_legitimation'] = self.c_t_prf_for_key_legitimation 
            
             
        # Libraty tags
        self.library_tags = {}
        self.library_tags['t_mac_key_generation_time'] = self.library_tag
        self.library_tags['t_generate_compare_mac'] = self.library_tag
        self.library_tags['t_generate_mac'] = self.library_tag        
        self.library_tags['t_key_exchange_encryption'] = self.library_tag
        self.library_tags['t_key_exchange_decryption'] = self.library_tag
        self.library_tags['t_prf_for_key_legitimation'] = self.library_tag 
         
    
    def get_function_map(self):
        ''' returns the function_map that maps the timing parameters to 
            functions that are called when the timing parameters are accessed
            
            
            Input:    -
            Output:   function_map    dictionary        maps timing parameters to functions. 
                                                        Key:     settings identifier
                                                        Value:   method called for this setting 
        '''
        return self.function_map

    
    def c_t_mac_key_generation_time(self, mac_alg, mac_keylen):
        ''' key generation with AES is a Random Function so same as a PRF'''
        try:
            # extract information
            algorithm = EnumTrafor().to_value(SymAuthMechEnum.AES)
            key_len = EnumTrafor().to_value(mac_keylen)
            
            # read Database
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_mac_key_generation_time'], mode='KEYGEN', keylen=key_len, alg=algorithm)
            
            # return result
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                L().log(603, 't_mac_key_generation_time')
        
            return 0.001
        except:
            logging.error("Error: Could not calculate the Value in 't_mac_key_generation_time'")
            return 0.000000001 
    
    
    def c_t_generate_compare_mac(self, input_size, mac_alg, mac_keylen):
        ''' generation of the comparison hash is a AES CMAC operation'''
        try:
            # extract infos
            L().log(605, mac_alg, input_size)
            algorithm = EnumTrafor().to_value(mac_alg)
            key_len = EnumTrafor().to_value(mac_keylen)
            alg_mode = "CMAC"
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(alg_mode=alg_mode, lib=self.library_tags['t_generate_compare_mac'], keylen=key_len, mode='ENCRYPTION', alg=algorithm, data_size=input_size)
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_generate_compare_mac')
            return 0.01  # self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        except:
            logging.error("Error: Could not calculate the Value in 't_generate_compare_mac'")
            return 0.000000001
        return 0
    
    
    def c_t_generate_mac(self, input_size, mac_alg, mac_keylen):
        ''' generation of the comparison hash is a AES CMAC operation'''
        try:
            # extract infos
            L().log(605, mac_alg, input_size)
            algorithm = EnumTrafor().to_value(mac_alg)
            key_len = EnumTrafor().to_value(mac_keylen)
            alg_mode = "CMAC"
            
            # DB Lookup
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_generate_compare_mac'], keylen=key_len, mode='ENCRYPTION', alg=algorithm, alg_mode=alg_mode, data_size=input_size)
            
            # return value
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)  
            else: 
                L().log(603, 't_generate_mac')
            return 0.01  # self.settings['t_reg_msg_hash'] = 'ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG'
        except:
            logging.error("Error: Could not calculate the Value in 't_generate_mac'")
            return 0.000000001
        return 0
    
    
    def c_t_key_exchange_encryption(self, input_size, enc_alg, enc_keylen, enc_alg_option):
        ''' public encryption or alternatively symmetric encryption with masterkey'''
        try:
            
            # extract information
            L().log(604, enc_alg, enc_keylen, input_size)
            
            algorithm = EnumTrafor().to_value(enc_alg)
            key_len = EnumTrafor().to_value(enc_keylen)
            alg_mode = EnumTrafor().to_value(enc_alg_option)
            
            # Symmertic Encryption
            if isinstance(enc_alg, SymAuthMechEnum):
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_key_exchange_encryption'], mode='ENCRYPTION', keylen=key_len, alg=algorithm, alg_mode=alg_mode, data_size=input_size)
                
            # Asymmetric Encryption
            else:
                # read Database
                if enc_alg == AsymAuthMechEnum.ECC: 
                    db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_key_exchange_encryption'], mode='ENCRYPTION', param_len=key_len, alg=algorithm, data_size=input_size)
                    
                else: 
                    # RSA: have to slice the message and encrypt each of those
                    if input_size > ((float(key_len) / 8) - 11): size_to_enc_in = ceil((float(key_len) / 8) - 11)
                    else: size_to_enc_in = input_size
                    db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_key_exchange_encryption'], exp=enc_alg_option, mode='ENCRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_enc_in)
                    
                    # RSA: have to slice the message and encrypt each of those
                    nr_chuncks = math.ceil(input_size / ((float(key_len) / 8) - 11))
                    db_val = db_val * nr_chuncks
                
            # return result
            if db_val: return G().val_log_info(db_val, 602, db_val)        
            else:  L().log(603, 't_key_exchange_encryption')
        
            return 0.001  
        except:
            logging.error("Error: Could not calculate the Value in 't_key_exchange_encryption'")
            return 0.000000001
    
    
    def c_t_key_exchange_decryption(self, msg_size, dec_alg, dec_key_len, alg_option):
        ''' Private decryption or alternatively symmetric encryption with master key'''
        try:
            # extract information
            L().log(604, dec_alg, dec_key_len, msg_size)
            algorithm = EnumTrafor().to_value(dec_alg)
            key_len = EnumTrafor().to_value(dec_key_len)
            alg_mode = EnumTrafor().to_value(alg_option)
            
            # Symmertic Encryption
            if isinstance(dec_alg, SymAuthMechEnum):
                db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_key_exchange_encryption'], mode='DECRYPTION', keylen=key_len, alg=algorithm, alg_mode=alg_mode, data_size=msg_size)
            
            else:
                # read Database
                if dec_alg == AsymAuthMechEnum.ECC: 
                    db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_key_exchange_decryption'], mode='DECRYPTION', param_len=key_len, alg=algorithm, data_size=msg_size)
                    
                else: 
                    # RSA: have to slice the message and encrypt each of those
                    if msg_size > ((float(key_len) / 8) - 11): size_to_enc_in = ceil((float(key_len) / 8) - 11)
                    else: size_to_enc_in = msg_size
                    db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_key_exchange_decryption'], exp=alg_option, mode='DECRYPTION', keylen=key_len, alg=algorithm, data_size=size_to_enc_in)
                    
                    # RSA: have to slice the message and encrypt each of those
                    nr_chuncks = math.ceil(msg_size / ((float(key_len) / 8) - 11))
                    db_val = db_val * nr_chuncks
                    
            # return result
            if db_val: return G().val_log_info(db_val, 602, db_val)        
            else:  L().log(603, 't_key_exchange_decryption')
        
            return 0.001  
        except:
            logging.error("Error: Could not calculate the Value in 't_key_exchange_decryption'")
            return 0.000000001
    
    
    def c_t_prf_for_key_legitimation(self, mac_alg, mac_keylen):
        ''' key generation with AES is a Random Function so same as a PRF'''
        try:
            
            # extract information
            algorithm = EnumTrafor().to_value(SymAuthMechEnum.AES)
            key_len = EnumTrafor().to_value(AuKeyLengthEnum.bit_192)
            
            # read Database
            db_val = TimingDBMap().lookup_interpol(lib=self.library_tags['t_prf_for_key_legitimation'], mode='KEYGEN', keylen=key_len, alg=algorithm)
            
            # return result
            if db_val: 
                return G().val_log_info(db_val, 602, db_val)        
            else: 
                L().log(603, 't_prf_for_key_legitimation')
        
            return 0.001
        except:
            logging.error("Error: Could not calculate the Value in 't_prf_for_key_legitimation'")
            return 0.000000001 
