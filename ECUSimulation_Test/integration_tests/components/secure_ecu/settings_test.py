'''
Created on 25 May, 2015

Erzeuge automatisiert eine beliebige Konfiguration fuer eine ECU

Jeder Projektparameter muss einmal getestet werden
Jeder Timingparameter muss einmal getestet werden


1. Teste verschiedene Projektparameter
    - folgen daraus die richtigen Timingparameter?
    - folgen daraus die richtigen Projektparameter
     
2. Teste verschiedene Timingvariablen
    - folgen daraus die richtigen Timingparameter

3. Setzen von Timingvariablen: wird an jeder Stelle richtig getimeouted
    
4. Spiele einmal komplett durch welche Messages rumgeschickt werden
   und deren Groessen

5. Check ob erwartete Cipher/Cleartext Groessen fuer Timeout funktionen uebergeben wurden

Generator:
- erzeuge Test fuer jeden einzelnen Parameter
- pro Parameter feste Reihenfolge an Tests


Helpermethode: 
    - schreibt bei jedem Timeout mit wie lange der Timeout war
      und welche id das war
@author: artur.mrowca
'''
import numpy
import logging
import os
import random

from astropy.io.ascii.tests.common import assert_true

from api.core.api_core import APICore, TimingFunctionSet
from api.core.component_specs import RegularECUSpec, SimpleECUSpec, \
    SimpleBusSpec
import api.ecu_sim_api as api
from components.base.gateways.impl_can_gateway import CANGateway
from components.security.communication.stream import MessageStream
from components.security.ecu.types.impl_ecu_secure import SecureECU, \
    StdSecurECUTimingFunctions
from components.security.ecu.types.impl_sec_mod_lwa import StdSecurLwSecModTimingFunctions
from config import can_registration
from enums.sec_cfg_enum import CAEnum, AsymAuthMechEnum, AuKeyLengthEnum, \
    EnumTrafor
import unittest2 as unittest
from tools.general import General as G
from config.timing_db_admin import TimingDBMap
from components.security.encryption.encryption_tools import EncryptionSize
from numpy.core.defchararray import isnumeric


class SecureECUSettingsIntegrationTest(unittest.TestCase):
    '''
        Classes under test: (Regular)SecureECU, StdSecureECUTimingFunctions, SecureCommModule
    
        This class tests all settings in the following way:
        It generates a certain test environment and runs it
        for x seconds. Depending on the settings of the environment
        certain outcome values are expected.  
        
        All timeouts that are used anywhere in the code are tested separately
        
        Bei fixed timeout ist es einfach zu testen: nehme die id und setze den wert fix
        wenn geklappt gut wenn nicht assert false!
        z.b. 
        set_time(t_abc, 10)
        actual = G().used_timeouts(ABC), expected = 10
        
        Todo: Same for Sizes  
    '''

    # gehe alle timeout variablen nach der Reihe durch und teste ob sie je nach input
    # tun was sie sollen:
    # Vorgehen: Erzeuge pro Variable alle moeglichen Projektsettings die diese Variable
    #           beeinflussen
    #           -> teste dann ob timeout erwarteten wert hat

    '''===========================================================================
             Setup/Teardown
    ==========================================================================='''
    def setUp(self):    
        
        # Create a sample simulation
        self._init_part()
            
        self._ecu_creation_part()
        
        self._sec_mod_creation_part()
        
        self._bus_creation_part()

        self._ecu_to_sec_mod_part()
        
        self._set_streams_part()
    

    '''===========================================================================
             Project - Tests
    ==========================================================================='''
    def test_default_set(self):
        ''' 
        teste ob aus projekt.ini und timings.ini die richtigen Einstellungen rausgelesen wurden'''
        # TODO: Implement
    
    def test_all_project_variables_accessed(self):
        ''' 
        when variables are set here in the environment they should later on be set in 
        the Component itself. This test sets all variables to a random value and 
        checks the real value if it was set correctly 
        
        Todo: Add Algorithm Mode CBC, CCM... to this test
        '''
#         # DISABLED
        return
        
        
        # Prepare
        
        self._init_part()           
        test_dict = {}
        test_dict["Test_ECU_1"] = {}
        test_dict["Test_ECU_2"] = {}
        test_dict["Test_ECU_3"] = {}
        ecu_spec1 = RegularECUSpec(["Test_ECU_1"], 200, 200)
        ecu_spec1.add_sending_actions(150, 1.5, can_registration.CAN_TEST_MSG, "TEST STRING A", 50)        
        ecu_spec2 = RegularECUSpec(["Test_ECU_2"], 200, 200)     
        ecu_spec3 = SimpleECUSpec(["Test_ECU_3"], 200, 200)       
        
        # Generate random settings in ECUs        
        for ky in self._av_settings:            
            for ecu_spec in [ecu_spec1 , ecu_spec2 , ecu_spec3]:
                val = random.random()                                
                if ecu_spec == ecu_spec1: test_dict["Test_ECU_1"][ky] = val
                if ecu_spec == ecu_spec2: test_dict["Test_ECU_2"][ky] = val
                if ecu_spec == ecu_spec3: test_dict["Test_ECU_3"][ky] = val    
                                
                
                                
                ecu_spec.set_ecu_setting(ky, val)
        
        # Apply those settings
        self.ecu_group_1 = api.set_ecus(self.env, 1, 'RegularSecureECU', ecu_spec1)    
        self.ecu_group_2 = api.set_ecus(self.env, 1, 'RegularSecureECU', ecu_spec2)
        self.ecu_group_3 = api.set_ecus(self.env, 1, 'SecureECU', ecu_spec3) 
        t_set2 = TimingFunctionSet() 
        ecu_func_set = StdSecurECUTimingFunctions(main_library_tag="CyaSSL")
        for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
            t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
            api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2) 
        
        self._sec_mod_creation_part()        
        self._bus_creation_part()
        self._ecu_to_sec_mod_part()        
        self._set_streams_part()        
        api.build_simulation(self.env)
                
        # Check if all ECU settings were set correctly  
        for ecu in self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3:
            if ecu.ecuSW.comm_mod.authorizer.SCCM_ECU_REQ_MSG_SIZE != test_dict[ecu.ecu_id]['p_req_msg_sending_size']: 
                print("Went wrong at %s" % "p_req_msg_sending_size")
                assert_true(False)                
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_REG_MSG_SIZE != test_dict[ecu.ecu_id]['p_reg_msg_sending_size']: 
                print("Went wrong at %s" % "p_reg_msg_sending_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.ECU_CERT_SIZE != test_dict[ecu.ecu_id]['p_ecu_cert_sending_size']: 
                print("Went wrong at %s" % "p_ecu_cert_sending_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.ECU_CERT_HASHING_MECH != test_dict[ecu.ecu_id]['p_ecu_auth_cert_hash_mech']: 
                print("Went wrong at %s" % "p_ecu_auth_cert_hash_mech")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.ECU_CERT_ENCRYPTION_MECH != test_dict[ecu.ecu_id]['p_ecu_auth_cert_enc_mech']: 
                print("Went wrong at %s" % "p_ecu_auth_cert_enc_mech")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.ECU_CERT_KEYL != test_dict[ecu.ecu_id]['p_ecu_auth_cert_enc_keylen']: 
                print("Went wrong at %s" % "p_ecu_auth_cert_enc_keylen")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.ECU_CERT_CA_LEN != test_dict[ecu.ecu_id]['p_ecu_auth_cert_ca_len']: 
                print("Went wrong at %s" % "p_ecu_auth_cert_ca_len")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.ECU_CERT_SIZE_HASH_TO_SIGN != test_dict[ecu.ecu_id]['p_ecu_auth_cert_hash_unsigned_size']: 
                print("Went wrong at %s" % "p_ecu_auth_cert_hash_unsigned_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.ECU_CERT_SIZE_HASH_SIGNED != test_dict[ecu.ecu_id]['p_ecu_auth_cert_hash_signed_size']: 
                print("Went wrong at %s" % "p_ecu_auth_cert_hash_signed_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SSMA_REG_MSG_CIPHER_SIZE_INNER != test_dict[ecu.ecu_id]['p_reg_msg_inner_cipher_size']: 
                print("Went wrong at %s" % "p_reg_msg_inner_cipher_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SSMA_REG_MSG_CIPHER_SIZE_OUTER != test_dict[ecu.ecu_id]['p_reg_msg_outter_cipher_size']: 
                print("Went wrong at %s" % "p_reg_msg_outter_cipher_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SECMOD_CERT_HASHING_MECH != test_dict[ecu.ecu_id]['p_sec_mod_cert_hashing_mech']: 
                print("Went wrong at %s" % "p_sec_mod_cert_hashing_mech")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SECMOD_CERT_ENCRYPTION_MECH != test_dict[ecu.ecu_id]['p_sec_mod_cert_enc_mech']: 
                print("Went wrong at %s" % "p_sec_mod_cert_enc_mech")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SECMOD_CERT_KEYL != test_dict[ecu.ecu_id]['p_sec_mod_cert_enc_keylen']: 
                print("Went wrong at %s" % "p_sec_mod_cert_enc_keylen")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SECMOD_CERT_CA_LEN != test_dict[ecu.ecu_id]['p_sec_mod_cert_ca_len']: 
                print("Went wrong at %s" % "p_sec_mod_cert_ca_len")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SECMOD_CERT_SIZE_HASH_TO_SIGN != test_dict[ecu.ecu_id]['p_sec_mod_cert_hash_size']: 
                print("Went wrong at %s" % "p_sec_mod_cert_hash_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SECMOD_CERT_SIZE_HASH_SIGNED != test_dict[ecu.ecu_id]['p_sec_mod_cert_signed_hash_size']: 
                print("Went wrong at %s" % "p_sec_mod_cert_signed_hash_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.ecu_sym_enc_alg != test_dict[ecu.ecu_id]['p_ecu_sym_key_alg']: 
                print("Went wrong at %s" % "p_ecu_sym_key_alg")
                assert_true(False)
            if ecu.ecuSW.comm_mod.ecu_sym_enc_keyl != test_dict[ecu.ecu_id]['p_ecu_sym_key_keylen']: 
                print("Went wrong at %s" % "p_ecu_sym_key_keylen")
                assert_true(False)
            if ecu.ecuSW.comm_mod.assym_enc_alg != test_dict[ecu.ecu_id]['p_reg_msg_outter_enc_alg']: 
                print("Went wrong at %s" % "p_reg_msg_outter_enc_alg")
                assert_true(False)
            if ecu.ecuSW.comm_mod.assym_enc_key_len != test_dict[ecu.ecu_id]['p_reg_msg_outter_enc_keylen']: 
                print("Went wrong at %s" % "p_reg_msg_outter_enc_keylen")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_REG_MSG_HASH != test_dict[ecu.ecu_id]['p_reg_msg_hash_alg']: 
                print("Went wrong at %s" % "p_reg_msg_hash_alg")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SSMA_SECM_PUB_ENC_ALG != test_dict[ecu.ecu_id]['p_reg_msg_inner_enc_method']: 
                print("Went wrong at %s" % "p_reg_msg_inner_enc_method")
                assert_true(False)  #             
            if ecu.ecuSW.comm_mod.authenticator.SSMA_SECM_PUB_ENC_KEY_LEN != test_dict[ecu.ecu_id]['p_reg_msg_inner_enc_keylen']: 
                print("Went wrong at %s" % "p_reg_msg_inner_enc_keylen")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_REG_MSG_HASH_LEN != test_dict[ecu.ecu_id]['p_reg_msg_outter_hash_size']: 
                print("Went wrong at %s" % "p_reg_msg_outter_hash_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SSMA_REG_MSG_CT_SIZE_INNER != test_dict[ecu.ecu_id]['p_reg_msg_inner_content_size']: 
                print("Went wrong at %s" % "p_reg_msg_inner_content_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_CONF_MSG_CIPHER_SIZE != test_dict[ecu.ecu_id]['p_conf_msg_cipher_size']: 
                print("Went wrong at %s" % "p_conf_msg_cipher_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_CONF_MSG_SIZE != test_dict[ecu.ecu_id]['p_ecu_auth_conf_msg_size']: 
                print("Went wrong at %s" % "p_ecu_auth_conf_msg_size")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG != test_dict[ecu.ecu_id]['t_reg_msg_hash']: 
                print("Went wrong at %s" % "t_reg_msg_hash")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_OUTTER != test_dict[ecu.ecu_id]['t_reg_msg_outter_enc']: 
                print("Went wrong at %s" % "t_reg_msg_outter_enc")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_DEC_CONF_MSG != test_dict[ecu.ecu_id]['t_conf_msg_dec_time']: 
                print("Went wrong at %s" % "t_conf_msg_dec_time")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ADV_SEC_MOD_CERT_VAL != test_dict[ecu.ecu_id]['t_adv_msg_secmodcert_enc']: 
                print("Went wrong at %s" % "t_adv_msg_secmodcert_enc")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY != test_dict[ecu.ecu_id]['t_reg_msg_sym_keygen']: 
                print("Went wrong at %s" % "t_reg_msg_sym_keygen")
                assert_true(False)
            if ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_INNER != test_dict[ecu.ecu_id]['t_reg_msg_inner_enc']: 
                print("Went wrong at %s" % "t_reg_msg_inner_enc")
                assert_true(False) 
        
        assert_true(True) 

    '''===========================================================================
             Private methods
    ==========================================================================='''
    def _init_part(self):
        self._av_proj_settings = [ i for n, i in enumerate(list(SecureECU().settings.keys())) if i[0] != 't' ]
        self._av_timing_settings = [ i for n, i in enumerate(list(SecureECU().settings.keys())) if i[0] == 't' ]
        self._av_settings = list(SecureECU().settings.keys())


        # Setup the environment with default settings
        api_log_path = os.path.join(os.path.dirname(__file__), "api.log")
        api.show_logging(logging.INFO, api_log_path, False)
        
        # Create an environment
        self.env = api.create_environment(160)
          
    def _ecu_spec_creation(self):
        self.ecu_spec_1 = RegularECUSpec(["Test_ECU_1"], 200, 200)
        self.ecu_spec_1.add_sending_actions(150, 1.5, can_registration.CAN_TEST_MSG, "TEST STRING A", 167)        
        
        # Receiver
        self.ecu_spec_2 = RegularECUSpec(["Test_ECU_2"], 200, 200)  
        self.ecu_spec_3 = RegularECUSpec(["Test_ECU_3"], 200, 200)        
        
    def _ecu_spec_application(self):
        
        # Sender     
        self.ecu_group_1 = api.set_ecus(self.env, 1, 'RegularSecureECU', self.ecu_spec_1) 
        self.ecu_group_2 = api.set_ecus(self.env, 1, 'RegularSecureECU', self.ecu_spec_2) 
        self.ecu_group_3 = api.set_ecus(self.env, 1, 'SecureECU', self.ecu_spec_3)  
        
    def _ecu_spec_timing_application(self):        
        t_set2 = TimingFunctionSet() 
        ecu_func_set = StdSecurECUTimingFunctions(main_library_tag='CyaSSL')
        for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
            t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
            api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)  
        
    def _ecu_creation_part(self):
        
        self._ecu_spec_creation()
        
        self._ecu_spec_application()

        self._ecu_spec_timing_application()
            
    def _ecu_to_sec_mod_part(self):
        
        # ECU to Security Module
        api.register_ecu_groups_to_secmod(self.env, self.sec_mod.ecu_id, [self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3])
        certeros = api.create_cert_manager()
        ecu_ids = []
        for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
            if isinstance(ecu, CANGateway):
                continue   
            ecu_ids += [ecu.ecu_id]
            api.generate_valid_ecu_cert_cfg(certeros, ecu.ecu_id, CAEnum.CA_L313, 'SEC 1', 0, float('inf'))
        api.generate_valid_sec_mod_cert_cfg(certeros, 'SEC 1', CAEnum.CA_L313, ecu_ids, 0, float('inf'))
        api.apply_certification(self.env, certeros)

    def _sec_mod_creation_part(self):
        
        # Security Module
        ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)  
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)  
        self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]
        
        t_set = TimingFunctionSet()
        ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag='CyaSSL')
        t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
        api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
    
    def _bus_creation_part(self):
        # BUS
        bus_spec = SimpleBusSpec(['CAN_0', 'CAN_1', 'CAN_2'])
        self.bus_group = api.set_busses(self.env, 3, 'StdCANBus', bus_spec)

        api.connect_bus_by_obj(self.env, 'CAN_0', self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3 + [self.sec_mod])
        
    def _set_streams_part(self):
               
        # Add Streams
        stream_1 = MessageStream('Test_ECU_1', ['Test_ECU_2', 'Test_ECU_3'], can_registration.CAN_TEST_MSG, float('inf'), 0, float('inf'))
        api.add_allowed_stream(self.env, 'SEC 1', stream_1)
        api.autoset_gateway_filters(self.env, 'SEC 1')
        
    def _run_part(self):
#         import gui.direct_view_window
#         my_moni = Monitor()        
#         api.connect_monitor(self.env, my_moni, 5)  # Connect monitor to environment        
#         self.direct_view = gui.direct_view_window.DirectViewer()
#         
        api.build_simulation(self.env)
        api.run_simulation(self.env)

    




class TestConfigComponent(object):
    
    def __init__(self, algo=None, ca_len=None, key_len=None, lib=None, hash_mech=None, msg_size=None, expected_outcome=None, exp=None, validity=99999, mode=None):
        self.algo = algo
        self.key_len = key_len
        self.lib = lib
        
        self.ca_len = ca_len
        self.hash_mech = hash_mech
        self.mode = mode
        self.exponent = exp
        self.msg_size = msg_size
        self.validity = validity
        self.expected = expected_outcome








