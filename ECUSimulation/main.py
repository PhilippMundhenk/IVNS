'''
Created on 14 May, 2015

Mach etwas

dann 2 3 Zeilen Code schalte GUI dazu:
    sage welche Views will ich sehen 
    
zeigt abgespeckte gui an

@author: artur.mrowca
'''

import logging
import os
from api.core.api_core import TimingFunctionSet, APICore
import api.ecu_sim_api as api
from components.security.ecu.types.impl_ecu_secure import StdSecurECUTimingFunctions
from components.security.ecu.types.impl_sec_mod_lwa import StdSecurLwSecModTimingFunctions
from components.security.encryption.encryption_tools import EncryptionSize
from enums.sec_cfg_enum import CAEnum, AsymAuthMechEnum, AuKeyLengthEnum, \
    HashMechEnum, SymAuthMechEnum
from components.security.communication.stream import MessageStream
import tools
from components.base.gateways.impl_can_gateway import CANGateway
from config import can_registration
from api.core.component_specs import RegularECUSpec, SimpleECUSpec, \
    SimpleBusCouplerSpec, SimpleBusSpec
from io_processing.surveillance import Monitor

 

# ---------------------------------- TEMPORARY FOR TESTING  ---------------------------------- 
def set_settings_sec_mod(sec_spec):
    '''===========================================================================
         Sending sizes
    ==========================================================================='''
    sec_spec.set_ecu_setting('p_sec_mod_cert_size', 1300)  # 1300
     
     
    '''===========================================================================
         Certification
    ==========================================================================='''
    sec_spec.set_ecu_setting('p_sec_mod_cert_ca_len', 3)    
    sec_spec.set_ecu_setting('p_sec_mod_cert_hashing_mech', HashMechEnum.MD5)  
    sec_spec.set_ecu_setting('p_sec_mod_cert_enc_mech', AsymAuthMechEnum.RSA)  
    sec_spec.set_ecu_setting('p_sec_mod_cert_enc_keylen', AuKeyLengthEnum.bit_1024) 
    sec_spec.set_ecu_setting('p_sec_mod_cert_hash_size', 16)  # Size of the hash to be signed
 
    # ECUs Certificate unsigned hash size
    sec_spec.set_ecu_setting('p_ecu_auth_cert_hash_unsigned_size', 1300)  
#     sec_spec.set_ecu_setting('p_ecu_auth_cert_hash_signed_size', 1300)  
 
    '''===========================================================================
         ECU Authentication
    ==========================================================================='''
    sec_spec.set_ecu_setting('p_reg_msg_hash_alg', HashMechEnum.MD5)
    sec_spec.set_ecu_setting('p_reg_msg_inner_enc_method', AsymAuthMechEnum.RSA)    
    sec_spec.set_ecu_setting('p_reg_msg_inner_enc_keylen', AuKeyLengthEnum.bit_1024)    
    sec_spec.set_ecu_setting('p_reg_msg_inner_content_size', 100)    
    sec_spec.set_ecu_setting('p_reg_msg_outter_enc_alg', AsymAuthMechEnum.RSA)    
    sec_spec.set_ecu_setting('p_reg_msg_outter_enc_keylen', AuKeyLengthEnum.bit_1024)    
    sec_spec.set_ecu_setting('p_ecu_auth_conf_msg_size', 50)    
     
    '''===========================================================================
         Stream Authorization
    ==========================================================================='''
    sec_spec.set_ecu_setting('p_req_msg_content_size', 50)    
    sec_spec.set_ecu_setting('p_grant_msg_content_size', 80) 
     
    sec_spec.set_ecu_setting('p_str_auth_ses_key_enc_alg', SymAuthMechEnum.AES)   
    sec_spec.set_ecu_setting('p_str_auth_ses_key_enc_keylen', AuKeyLengthEnum.bit_128)   
    sec_spec.set_ecu_setting('p_str_auth_ses_key_validity', 2000)     
 
def set_settings_ecu(ecu_spec):
    '''===========================================================================
         Sending sizes
    ==========================================================================='''
    ecu_spec.set_ecu_setting('p_ecu_cert_sending_size', 1300)  # 1300
#     ecu_spec.set_ecu_setting('p_sec_mod_cert_hash_size', 1300)
 
    '''===========================================================================
         Certification
    ==========================================================================='''
    ecu_spec.set_ecu_setting('p_ecu_auth_cert_ca_len', 3)    
    ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_mech', HashMechEnum.MD5)  
    ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_unsigned_size', 16)          
    ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_mech', AsymAuthMechEnum.RSA)  
    ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_keylen', AuKeyLengthEnum.bit_1024) 
    ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_signed_size', EncryptionSize().output_size(16, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_1024, 'HASH'))
 
    '''===========================================================================
         ECU Authentication
    ==========================================================================='''
    ecu_spec.set_ecu_setting('p_ecu_sym_key_alg', SymAuthMechEnum.AES)
    ecu_spec.set_ecu_setting('p_ecu_sym_key_keylen', AuKeyLengthEnum.bit_128)
 
    '''===========================================================================
         Stream Authorization
    -> Optional
    ==========================================================================='''
 
# register_ecu_classes(r"C:\Users\artur.mrowca\workspace\ECUSimulation\components\base\gateways")
api_log_path = os.path.join(os.path.dirname(__file__), "logs/api.log")
api.show_logging(logging.INFO, api_log_path, True)
my_env = api.create_environment(180)
 
# Simple ECU CREATION
# ecu_spec = SimpleECUSpec([], 200, 200)
# set_settings_ecu(ecu_spec)
# ecu_group_0 = api.set_ecus(my_env, 7, 'SecureECU', ecu_spec)
 
# Sending ECU: Sends data in fixed intervals 
ecu_spec = RegularECUSpec(["RegularSecureECU_15"], 2000, 2000)
set_settings_ecu(ecu_spec)
 
ecu_spec.set_ecu_setting('p_stream_hold', False)  # Define holding behavior per ECU
ecu_spec.set_ecu_setting('p_stream_req_min_interval', 5)
 
ecu_spec.add_sending_actions(150, 0.6, can_registration.CAN_TEST_MSG, "TEST STRING A", 50)
ecu_spec.add_sending_actions(150, 0.3, 16, "TEST STRING B", 50)  # sends at 300, 308, 316, ...
 
ecu_group_1 = api.set_ecus(my_env, 1, 'RegularSecureECU', ecu_spec)
 
 
ecu_spec = SimpleECUSpec(['SEC 1'], 2000, 2000)
ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 100)  
ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 1000)  
 
set_settings_sec_mod(ecu_spec)
sec_mod_group = api.set_ecus(my_env, 1, 'SecLwAuthSecurityModule', ecu_spec)
 
ecu_spec = RegularECUSpec(["TEST ECU 9", "TEST ECU 10"], 2000, 2000)
set_settings_ecu(ecu_spec)
ecu_group_3 = api.set_ecus(my_env, 2, 'RegularSecureECU', ecu_spec)
 
ecu_spec = RegularECUSpec(["TEST ECU 11", "TEST ECU 12"], 2000, 2000)
set_settings_ecu(ecu_spec)
ecu_group_4 = api.set_ecus(my_env, 2, 'RegularSecureECU', ecu_spec)
 
#===============================================================================
#     GATEWAY CREATION
#===============================================================================
 
# GATEWAY CREATION
ecu_spec = SimpleBusCouplerSpec([])
ecu_spec.set_ecu_setting('t_transition_process', 2)  # Delay of the gateway
# ecu_spec.set_filter(can_registration.AUTH_MESSAGES + [can_registration.CAN_TEST_MSG, 500, 16])  # Add a filter to the gateway. Generally blocks those ids// do not use in combination with api.gateway_filter_bus
gateway_group_1 = api.set_ecus(my_env, 1, 'CANGateway', ecu_spec)
gateway_group_2 = api.set_ecus(my_env, 1, 'CANGateway', ecu_spec)
 
# BUS CREATION
bus_spec = SimpleBusSpec(['CAN_0', 'CAN_1', 'CAN_2'])
bus_group = api.set_busses(my_env, 3, 'NoArbitCANBus', bus_spec)

# CONNECT 7 ECUs and the SEC MOD to CAN 0 and 2 ECUs to CAN_1 and 2 ECUs to CAN 2
# CONNECT CAN 0 via GW1 to CAN 1 // CONNECT CAN 1 via GW 2 to CAN 2
api.connect_bus_by_obj(my_env, 'CAN_0', ecu_group_1 + sec_mod_group + gateway_group_1) 
api.connect_bus_by_obj(my_env, 'CAN_1', gateway_group_1 + ecu_group_3)
api.connect_bus_by_obj(my_env, 'CAN_2', ecu_group_4 + gateway_group_1)

# GATEWAY BUS DEPENDENT FILTER
# filters incoming messages, so all messages in fst that are coming from bus CAN_0 are allowed the rest is filtered
# GW1 allows only CAN_TEST_MSG to be forwarded when coming from can_0
# fst = [can_registration.CAN_TEST_MSG]
# scd = can_registration.AUTH_MESSAGES + [500]
 
# api.gateway_filter_bus(gateway_group_1, {'CAN_0':[1,2,3,4,5], 'CAN_1':[1,2,3,4,5,2730,511]})  
# api.gateway_filter_sending_bus(gateway_group_1, {'CAN_0':[1, 2, 3, 4, 2730, 5, 6, 7, 8, 9], 'CAN_1':[1, 2, 3, 4, 5, 6, 7, 8, 9, 2730, 511], 'CAN_2':[1, 2, 3, 4, 5, 6, 7, 8, 9, 2730, 511]})  
 
api.register_ecu_groups_to_secmod(my_env, sec_mod_group[0].ecu_id, [ecu_group_1 + ecu_group_3 + ecu_group_4 ])
 
certeros = api.create_cert_manager()
ecu_ids = []
for ecu in APICore()._ecu_list_from_groups([[ecu_group_1 + ecu_group_3 + ecu_group_4]]):  # UNINTENDED HACK
    if isinstance(ecu, CANGateway):
        continue   
    ecu_ids += [ecu.ecu_id]
    api.generate_valid_ecu_cert_cfg(certeros, ecu.ecu_id, CAEnum.CA_L313, 'SEC 1', 0, float('inf'))
api.generate_valid_sec_mod_cert_cfg(certeros, 'SEC 1', CAEnum.CA_L313, ecu_ids, 0, float('inf'))
api.apply_certification(my_env, certeros)
 
 
stream_1 = MessageStream('RegularSecureECU_15', ['SecureECU_1', 'TEST ECU 9', 'TEST ECU 11'], can_registration.CAN_TEST_MSG, float('inf'), 0, float('inf'))
stream_2 = MessageStream('RegularSecureECU_15', ['SecureECU_1', 'TEST ECU 12', 'SecureECU_5'], 16, float('inf'), 0, float('inf'))
# stream_3 = MessageStream('SecureECU_0', ['SecureECU_4', 'SecureECU_1', 'SecureECU_5'], 222, float('inf'), 0, float('inf'))
# stream_4 = MessageStream('SecureECU_3', ['SecureECU_0', 'SecureECU_1', 'SecureECU_5'], AbstractBusMessage.CAN_TEST_MSG_2, float('inf'), 0, float('inf'))
# stream_5 = MessageStream('SecureECU_4', ['TEST ECU 9', 'SecureECU_1', 'SecureECU_3'], 500, float('inf'), 0, float('inf'))
# stream_6 = MessageStream('RegularSecureECU_15', ["TEST ECU 10", 'SecureECU_1'], 16, float('inf'), 0, float('inf'))
 
api.add_allowed_stream(my_env, 'SEC 1', stream_1)
api.add_allowed_stream(my_env, 'SEC 1', stream_2)
# api.add_allowed_stream(my_env, 'SEC 1', stream_3)
# api.add_allowed_stream(my_env, 'SEC 1', stream_4)
# api.add_allowed_stream(my_env, 'SEC 1', stream_5)
# api.add_allowed_stream(my_env, 'SEC 1', stream_6)
 
t_set = TimingFunctionSet()
ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag='CyaSSL')
ecu_func_set.library_tags['t_ecu_auth_reg_msg_validate_cert'] = 'Crypto_Lib_SW'
 
t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
api.apply_timing_functions_set(my_env, 'SEC 1', t_set)
   
t_set2 = TimingFunctionSet() 
ecu_func_set = StdSecurECUTimingFunctions(main_library_tag='CyaSSL')
ecu_func_set.library_tags['t_adv_msg_secmodcert_enc'] = 'Crypto_Lib_SW'
 
# SET ALL GATEWAY FILTERS, Bus dependent from the streams
api.autoset_gateway_filters(my_env, 'SEC 1')
 
for ecu in APICore()._ecu_list_from_groups([[ecu_group_1 + ecu_group_3 + ecu_group_4]]):  # UNINTENDED HACK
    t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
    api.apply_timing_functions_set(my_env, ecu.ecu_id, t_set2)
     
    
# Save environment
# filepath = os.path.join(os.path.dirname(__file__), "environments/1.env")
# api.save_env_spec(my_env, filepath)  
# my_env = api.load_env_spec(filepath)
    
# Monitor Test (optional)
my_moni = Monitor()
api.connect_monitor(my_env, my_moni, 5)  # Connect monitor to environment


 
api.build_simulation(my_env)
api.run_simulation(my_env)
 
 

     


