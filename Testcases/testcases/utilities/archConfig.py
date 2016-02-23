'''
Created on 20 Aug, 2015

@author: artur.mrowca
'''
from config.specification_set import LWASpecPresets, TeslaSpecPresets, \
    TlsSpecPresets
from enums.sec_cfg_enum import HashMechEnum, AsymAuthMechEnum, AuKeyLengthEnum, \
    SymAuthMechEnum, PRF
import sys
import api.ecu_sim_api as api
import os
import logging
from io_processing.surveillance_handler import MonitorTags
from io_processing.result_interpreter.buffer_interpreter import BufferInterpreter
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter
from io_processing.result_interpreter.can_bus_interpreter import CanBusInterpreter
from io_processing.result_interpreter.abst_result_interpreter import InterpreterOptions
from enums.tls_enums import CompressionMethod
from configparser import ConfigParser

class ArchConfig(object):
    
    def __init__(self, file_path):
        if file_path != None: self.file_path = file_path
        else: self.file_path = False
    
    def config(self):
        
        
        #===============================================================================
        #     Define settings: LWA
        #===============================================================================
        
        LWASpecPresets().trigger_spec = [0, 99999999]  # authentication: start time and interval
        
        LWASpecPresets().sec_certificate_spec = [HashMechEnum.MD5, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, 1, 1000]  # security module certificate info:[hash,enc_alg, key_len/paramlen, exponent,number of CAs to root, size of certificate]
        LWASpecPresets().registration_first_part = [AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, 100]  # registration message first part:[enc_alg, key_len, exponent, size of inner part of reg message]
        LWASpecPresets().registration_second_part = [HashMechEnum.MD5, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537]  # registration message second part:[hash_alg, enc_alg, key_len, exponent]
        LWASpecPresets().ecu_certificate_spec = [HashMechEnum.MD5, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, 1, 1000]  # ecu certificate info:[hash,enc_alg, key_len/paramlen, exponent,number of CAs to root, size of certificate]        
        LWASpecPresets().confirmation_part = [100]  # confirmation message: [size]
        LWASpecPresets().ecu_key_info = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.CBC]  # ecu key specification: [algorithm, key_len, algorithm_mode]
        LWASpecPresets().hold_rule = [False, 10]  # hold on/off; minimal interval between two stream requests
        LWASpecPresets().request_spec = [100, 9999999999]  # request message [size, timeout maximum]
        LWASpecPresets().deny_spec = [100]  # deny message: [size]
        LWASpecPresets().grant_spec = [100]  # grant message: [size]
        
        
        
        LWASpecPresets().session_key_info = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.CBC]  # session key information: [algorithm, key_len, algorithm_mode]
        
        #===============================================================================
        #     Define settings: TLS
        #===============================================================================
        
        TlsSpecPresets().protocol_version = [3, 3]
        TlsSpecPresets().record_layer_spec = [CompressionMethod.NULL, SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.CBC]
        TlsSpecPresets().server_certificate_spec = [AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, HashMechEnum.MD5, 1, 1000]
        TlsSpecPresets().client_certificate_spec = [AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, HashMechEnum.MD5, 1, 1000]
        
        TlsSpecPresets().prf_master_key = PRF.DUMMY
        TlsSpecPresets().finished_message_spec = [HashMechEnum.MD5, PRF.DUMMY, PRF.DUMMY, PRF.DUMMY, PRF.DUMMY]
        
        TlsSpecPresets().mac_input_size = [60, 60 ]  # Input Size for the mac algorithm used in Record Layer at sending/receiveing side
        TlsSpecPresets().server_finished_size = [100, 100]  # size of server finished message on send and receive side
        TlsSpecPresets().client_finished_size = [100, 100]  # size of client finished message on send and receive side
        TlsSpecPresets().size_root_certificate = 1000
            
        TlsSpecPresets().cert_verify_size = 100  # size of certificate verify message
        TlsSpecPresets().client_key_exchange_size = 100
        TlsSpecPresets().client_hello_size = 60
        TlsSpecPresets().cert_request_size = 250
        TlsSpecPresets().server_hello_size = 60
        TlsSpecPresets().server_hello_done_size = 10
        
        #===============================================================================
        #     Define settings: Tesla
        #===============================================================================
        TeslaSpecPresets().setup_spec = [0, 999999, 400000] 
        TeslaSpecPresets().mac_spec = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128]  # mode is always CMAC
        TeslaSpecPresets().prf_create_chain = PRF.DUMMY 
        TeslaSpecPresets().prf_generate_mac_key = PRF.DUMMY 
        TeslaSpecPresets().key_exchange_spec = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.CBC, 100]
        
        TeslaSpecPresets().key_legid_mac_spec = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128]  # MAC Algorithm used to check if key is legid
        
        if self.file_path:
            self._config_from_file_path()
            return
        
    def config_gui_tags(self):
        ''' if the gui option was selected its settings should be
            adjusted here
            
            Input:    -
            Output:   plugs    list    list of plugins to be shown
        '''
        
        plugs = ['EventlineViewPlugin', 'MessageCountViewPlugin', "ConstellationViewPlugin"]
        
        return plugs
    
    def config_interpreter(self, my_reader, save_path_cp, save_path_can):
        ''' if the interpreter mode was selected its settings should
            be adjusted here
            
            Input:  my_reader     ResultReader    result reader connected to the monitor
                    save_path_cp  string          path to the checkpoints
            Output:   -
        '''
        
        save_path_buf = os.path.join(os.path.dirname(__file__), "../../logs/buffer.csv")

        my_reader.enable_handler(BufferInterpreter, [InterpreterOptions.CSV_FILE], save_path_buf)  
#         my_reader.enable_handler(CheckpointInterpreter, [InterpreterOptions.TIMING_FILE], save_path_cp)
        my_reader.enable_handler(EventlineInterpreter, [InterpreterOptions.CSV_FILE], save_path_cp) 
        my_reader.enable_handler(CanBusInterpreter, [InterpreterOptions.CSV_DR_FILE], save_path_can)   
        
    def config_rapid_tags(self):
        ''' if rapid mode is selected the tags to be shown should be set here
        
            Input:    -
            Output:   tags    list    list of MonitorInput objects that should be written to the csv file
        '''
        tags = [MonitorTags.CP_SEC_INIT_AUTHENTICATION, \
                MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE, \
                MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE, \
                MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE, \
                MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE, \
                MonitorTags.CP_SEC_CREATED_CMP_HASH_REG_MSG, \
                MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG, \
                MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE, \
                MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE, \
                MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE, \
                MonitorTags.CP_SEC_GENERATED_SESSION_KEY, \
                MonitorTags.CP_SEC_ENCRYPTED_DENY_MESSAGE, \
                MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE, \
                MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE, \
                MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE, \
                MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE, \
                MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE, \
                MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT, \
                MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE, \
                MonitorTags.CP_ECU_START_CREATION_REG_MESSAGE, \
                MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE, \
                MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE, \
                MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE, \
                MonitorTags.CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE, \
                MonitorTags.CP_ECU_SEND_REG_MESSAGE, \
                MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE, \
                MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE, \
                MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE, \
                MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE, \
                MonitorTags.CP_ECU_RECEIVE_DENY_MESSAGE, \
                MonitorTags.CP_ECU_DECRYPTED_DENY_MESSAGE, \
                MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE, \
                MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE, \
                MonitorTags.CP_SESSION_AVAILABLE_SEND_MESSAGE, \
                MonitorTags.CP_SEND_CLIENT_HELLO, \
                MonitorTags.CP_RECEIVE_CLIENT_HELLO, \
                MonitorTags.CP_SEND_ALERT_NO_CIPHERSUITE, \
                MonitorTags.CP_SEND_SERVER_HELLO, \
                MonitorTags.CP_SEND_SERVER_CERTIFICATE, \
                MonitorTags.CP_SEND_SERVER_KEYEXCHANGE,
                MonitorTags.CP_SEND_CERTIFICATE_REQUEST , \
                MonitorTags.CP_SEND_SERVER_HELLO_DONE , \
                MonitorTags.CP_RECEIVE_SERVER_HELLO , \
                MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE , \
                MonitorTags.CP_RECEIVE_SERVER_KEYEXCHANGE , \
                MonitorTags.CP_RECEIVE_CERTIFICATE_REQUEST , \
                MonitorTags.CP_RECEIVE_SERVER_HELLO_DONE , \
                MonitorTags.CP_SERVER_HELLO_DONE_VALIDATED_CERT , \
                MonitorTags.CP_SEND_CLIENT_CERTIFICATE , \
                MonitorTags.CP_INIT_SEND_CLIENT_KEYEXCHANGE , \
                MonitorTags.CP_ENCRYPTED_CLIENT_KEYEXCHANGE , \
                MonitorTags.CP_GENERATED_MASTERSEC_CLIENT_KEYEXCHANGE , \
                MonitorTags.CP_INIT_SEND_CERTIFICATE_VERIFY , \
                MonitorTags.CP_ENCRYPTED_CERTIFICATE_VERIFY , \
                MonitorTags.CP_SEND_CIPHER_SPEC , \
                MonitorTags.CP_INIT_CLIENT_FINISHED , \
                MonitorTags.CP_HASHED_CLIENT_FINISHED , \
                MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED , \
                MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE , \
                MonitorTags.CP_CLIENT_CERTIFICATE_VALIDATED , \
                MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE , \
                MonitorTags.CP_DECRYPTED_CLIENT_KEYEXCHANGE , \
                MonitorTags.CP_RECEIVE_CERTIFICATE_VERIFY , \
                MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY , \
                MonitorTags.CP_GENERATED_MASTER_SECRET_CERT_VERIFY , \
                MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC , \
                MonitorTags.CP_RECEIVE_CLIENT_FINISHED , \
                MonitorTags.CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH , \
                MonitorTags.CP_CLIENT_FINISHED_GENERATED_HASH_PRF , \
                MonitorTags.CP_RECEIVE_SERVER_FINISHED , \
                MonitorTags.CP_SERVER_FINISHED_HASHED_COMPARISON_HASH , \
                MonitorTags.CP_SERVER_FINISHED_GENERATED_HASH_PRF , \
                MonitorTags.CP_INIT_SERVER_FINISHED , \
                MonitorTags.CP_HASHED_SERVER_FINISHED , \
                MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED , \
                MonitorTags.CP_SERVER_AUTHENTICATED , \
                MonitorTags.CP_CLIENT_AUTHENTICATED, \
                MonitorTags.CP_RECEIVE_SIMPLE_MESSAGE, \
                MonitorTags.CP_INIT_EXCHANGE_FIRST_KEY_KN, \
                MonitorTags.CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN, \
                MonitorTags.CP_SETUP_INIT_CREATE_KEYS, \
                MonitorTags.CP_SETUP_FINISHED_CREATE_KEYS, \
                MonitorTags.CP_INIT_TRANSMIT_MESSAGE, \
                MonitorTags.CP_MACED_TRANSMIT_MESSAGE, \
    #             MonitorTags.CP_RECEIVED_SIMPLE_MESSAGE, \
    #             MonitorTags.CP_BUFFERED_SIMPLE_MESSAGE, \
    #             MonitorTags.CP_RETURNED_AUTHENTICATED_SIMPLE_MESSAGE, \
                MonitorTags.CP_RECEIVED_EXCHANGE_FIRST_KEY_KN, \
                MonitorTags.CP_DECRYPTED_EXCHANGE_FIRST_KEY_KN, \
                MonitorTags.CP_INIT_CHECK_KEY_LEGID, \
                MonitorTags.CP_CHECKED_KEY_LEGID, \
                MonitorTags.CP_INIT_VERIFYING_BUFFER_MESSAGE, \
                MonitorTags.CP_FINISHED_VERIFYING_BUFFER_MESSAGE, \
                MonitorTags.CP_SEND_SYNC_MESSAGE, \
                MonitorTags.CP_SEND_SYNC_RESPONSE_MESSAGE, \
                MonitorTags.CP_RECEIVE_SYNC_RESPONSE_MESSAGE, \
#                 MonitorTags.CB_DONE_PROCESSING_MESSAGE, \
#                 MonitorTags.CB_PROCESSING_MESSAGE\
                ]
        
        return tags
        
    def bus_numbers(self, a_buses_min, a_buses_max, buses, buses_min, buses_max):
        ''' determines the number of ecus depending on the
            inputed arguments
            
            Input:  buses_min             integer    proposed minimum number of buses
                    buses_max             integer    proposed maximum number of buses
                    buses                 integer    number of buses
            Output: buses_min             integer    actual minimum number of buses
                    buses_max             integer    actual maximum number of buses
        '''    
        if ((a_buses_max is None) & (a_buses_min is None)):
            if buses is not None:
                buses_max = buses_min = buses
        elif ((a_buses_max is None) | (a_buses_min is None)):
            print("Please specify lower and upper bound for buses, or use -b")
            sys.exit(2)
        else:
            buses_max = a_buses_max
            buses_min = a_buses_min
            
        return buses_max, buses_min
    
    def ecu_numbers(self, ecus_min, ecus_max, ecus, numberOfECUs_max, numberOfECUs_min):
        ''' determines the number of ecus depending on the
            inputed arguments
            
            Input:  ecus_min            integer    proposed minimum number of ecus
                    ecus_max            integer    proposed maximum number of ecus
                    ecus                integer    number of ecus
            Output: numberOfECUs_min    integer    actual minimum number of ecus
                    numberOfECUs_max    integer    actual maximum number of ecus
        '''            
        if ((ecus_max is None) & (ecus_min is None)):
            if ecus is not None:
                numberOfECUs_max = numberOfECUs_min = ecus
        elif ((ecus_max is None) | (ecus_min is None)):
            print("Please specify lower and upper bound for ECUs, or use -e")
            sys.exit(2)
        else:
            numberOfECUs_max = ecus_max
            numberOfECUs_min = ecus_min        
        return numberOfECUs_max, numberOfECUs_min
    
    def enable_logging(self, log, logtofile):
        ''' starts the logging over the api if defined by
            the given sys argument
            
            Input:  log            boolean    true if logging on
                    logtofile      boolean    true if logging to file is on
            Output: -
        '''       
        api_log_path = os.path.join(os.path.dirname(__file__), "../../logs/api.log")
        api.show_logging(logging.INFO, api_log_path, True)         
        if log:
            if logtofile:
                api_log_path = os.path.join(os.path.dirname(__file__), "../../logs/api.log")
                api.show_logging(logging.INFO, api_log_path, True)
            else:
                api.console_logging(logging.INFO, True)
        else:
            api.console_logging(logging.INFO, False)
    
    def msg_numbers(self, a_msgs_min, a_msgs_max, msgs, msgs_min, msgs_max):
        ''' determines the number of msgs depending on the
            inputed arguments
            
            Input:  msgs_min             integer    proposed minimum number of msgs
                    msgs_max             integer    proposed maximum number of msgs
                    msgs                 integer    number of msgs
            Output: msgs_min             integer    actual minimum number of msgs
                    msgs_max             integer    actual maximum number of msgs
        '''    
        if ((a_msgs_max is None) & (a_msgs_min is None)):
            if msgs is not None:
                msgs_max = msgs_min = msgs
        elif ((a_msgs_max is None) | (a_msgs_min is None)):
            print("Please specify lower and upper bound for msgs, or use -b")
            sys.exit(2)
        else:
            msgs_max = a_msgs_max
            msgs_min = a_msgs_min
            
        return msgs_max, msgs_min
        
    def std_authenticated(self, authenticated):
        ''' if input is not empty returns true else
            false
        
            Input:  authenticated    string     indicates if authentication set on
            Output: bool             boolean    true if the given string is not empty
        '''
        if authenticated:
            return True
        return False
        
    def std_path(self, os_path, output, rel_path):
        ''' this method returns the cp_path depending
            on the inputed sys arguments
            Input:    output    string    argument    
                      rel_path  string    relative path to destination
            Output:   output    string    standard value         
        '''
        if output:
            save_path = os.path.join(os_path, output)
        else:
            save_path = os.path.join(os_path, rel_path)
        
        return save_path
            
    def std_ecu_type(self, ecu_type):
        ''' this method returns the ecu_type depending
            on the inputed sys arguments
            Input:    ecu_type    string    argument
            Output:   ecu_type    string    standard value         
        '''
        if ecu_type == None:
            return "lw_auth"
        return ecu_type
        
    def std_variant(self, variant):
        ''' this method returns the variant depending
            on the inputed sys arguments
            Input:    variant    string    argument
            Output:   variant    string    standard value         
        '''
        if variant == None:
            return "rapid"
        return variant
    
    def _config_from_file_path(self):
        
        cfg = ConfigParser()
        cfg.read(self.file_path)
        
        map = self._cfg_sec_map(cfg, "Test")
    
                 
        #===============================================================================
        #     Define settings: LWA
        #===============================================================================
         
        LWASpecPresets().trigger_spec = [0, 99999999]  # authentication: start time and interval
         
        LWASpecPresets().sec_certificate_spec = [eval(map["hash_mech"]), eval(map["asym_algorithm"]), eval(map["asym_key_length"]), eval(map["asym_option"]), eval(map["ca_length"]), 1000]  # security module certificate info:[hash,enc_alg, key_len/paramlen, exponent,number of CAs to root, size of certificate]
         
        LWASpecPresets().registration_first_part = [eval(map["asym_algorithm"]), eval(map["asym_key_length"]), eval(map["asym_option"]), 100]  # registration message first part:[enc_alg, key_len, exponent, size of inner part of reg message]
        LWASpecPresets().registration_second_part = [eval(map["hash_mech"]), eval(map["asym_algorithm"]), eval(map["asym_key_length"]), eval(map["asym_option"])]  # registration message second part:[hash_alg, enc_alg, key_len, exponent]
        LWASpecPresets().ecu_certificate_spec = [eval(map["hash_mech"]), eval(map["asym_algorithm"]), eval(map["asym_key_length"]), eval(map["asym_option"]), eval(map["ca_length"]), 1000]  # ecu certificate info:[hash,enc_alg, key_len/paramlen, exponent,number of CAs to root, size of certificate]
         
        LWASpecPresets().confirmation_part = [100]  # confirmation message: [size]
         
        LWASpecPresets().ecu_key_info = [eval(map["sym_algorithm"]), eval(map["sym_key_length"]), eval(map["sym_mode"])]  # ecu key specification: [algorithm, key_len, algorithm_mode]
        LWASpecPresets().hold_rule = [False, 10]  # hold on/off; minimal interval between two stream requests
         
        LWASpecPresets().request_spec = [100, 9999999999]  # request message [size, timeout maximum]
         
        LWASpecPresets().deny_spec = [100]  # deny message: [size]
        LWASpecPresets().grant_spec = [100]  # grant message: [size]
         
        LWASpecPresets().session_key_info = [eval(map["sym_algorithm"]), eval(map["sym_key_length"]), eval(map["sym_mode"])]  # session key information: [algorithm, key_len, algorithm_mode]

        
        #===============================================================================
        #     Define settings: TLS
        #===============================================================================
        
        TlsSpecPresets().protocol_version = [3, 3]
        TlsSpecPresets().record_layer_spec = [CompressionMethod.NULL, eval(map["sym_algorithm"]), eval(map["sym_key_length"]), eval(map["sym_algorithm"]), eval(map["sym_key_length"]), eval(map["sym_mode"])]
        TlsSpecPresets().server_certificate_spec = [eval(map["asym_algorithm"]), eval(map["asym_key_length"]), eval(map["asym_option"]), eval(map["hash_mech"]), eval(map["ca_length"]), 1000]
        TlsSpecPresets().client_certificate_spec = [eval(map["asym_algorithm"]), eval(map["asym_key_length"]), eval(map["asym_option"]), eval(map["hash_mech"]), eval(map["ca_length"]), 1000]
        
        TlsSpecPresets().prf_master_key = PRF.DUMMY
        TlsSpecPresets().finished_message_spec = [eval(map["hash_mech"]), PRF.DUMMY, PRF.DUMMY, PRF.DUMMY, PRF.DUMMY]
        
        TlsSpecPresets().mac_input_size = [60, 60 ]  # Input Size for the mac algorithm used in Record Layer at sending/receiveing side
        TlsSpecPresets().server_finished_size = [100, 100]  # size of server finished message on send and receive side
        TlsSpecPresets().client_finished_size = [100, 100]  # size of client finished message on send and receive side
        TlsSpecPresets().size_root_certificate = 1000
            
        TlsSpecPresets().cert_verify_size = 100  # size of certificate verify message
        TlsSpecPresets().client_key_exchange_size = 100
        TlsSpecPresets().client_hello_size = 60
        TlsSpecPresets().cert_request_size = 250
        TlsSpecPresets().server_hello_size = 60
        TlsSpecPresets().server_hello_done_size = 10
        
        #===============================================================================
        #     Define settings: Tesla
        #===============================================================================
#         TeslaSpecPresets().setup_spec = [0, 999999, 300000] 
        TeslaSpecPresets().mac_spec = [eval(map["sym_algorithm"]), eval(map["sym_key_length"])]
        TeslaSpecPresets().prf_create_chain = PRF.DUMMY 
        TeslaSpecPresets().prf_generate_mac_key = PRF.DUMMY 
        TeslaSpecPresets().key_exchange_spec = [eval(map["asym_algorithm"]), eval(map["asym_key_length"]), eval(map["asym_option"]), 100]
        
        TeslaSpecPresets().key_legid_mac_spec = [eval(map["sym_algorithm"]), eval(map["sym_key_length"])]  # MAC Algorithm used to check if key is legid
        


    def _cfg_sec_map(self, cfg, section):
        ''' Maps the data read out of the ini file to a dictionary 
            
            Input:  config          ConfigParser    ConfigParser object holding the information
                    section         string          name of the section that is currently read out  
            Output: el_dict         dictionary      contains the information about elements mapped
        '''
        # initialize
        dict1 = {}
        options = cfg.options(section)
        
        # get options and write dict
        for option in options:
            try:
                dict1[option] = cfg.get(section, option)
            except:
                logging.info("\texception on %s!" % option)
                dict1[option] = None
        return dict1
