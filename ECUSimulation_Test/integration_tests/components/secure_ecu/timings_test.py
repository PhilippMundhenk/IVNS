'''
Testing the timeout values
If they were accessed correctly and if they have
the expected values depending on the set algorithms
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


class SecureECUTimingIntegrationTest(unittest.TestCase):
    '''
        Classes under test: (Regular)SecureECU, StdSecureECUTimingFunctions, SecureCommModule
    
        This class tests all timings in the following way:
        It generates a certain test environment and runs it
        for x seconds. Depending on the settings of the environment
        certain outcome timing values are expected.  
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
             Timing - Tests
    ==========================================================================='''
     
    def test_all_timing_variables_accessed(self):
        ''' 
        some variables use a constant and some a function. This 
            method tests if the settings are invoked correctly 
        '''
        # DISABLED
        
        
        
        # Prepare
        api.build_simulation(self.env)
        self._init_part()           
        test_dict = {}
        test_dict["Test_ECU_1"] = {}
        test_dict["Test_ECU_2"] = {}
        test_dict["Test_ECU_3"] = {}
        ecu_spec1 = RegularECUSpec(["Test_ECU_1"], 200, 200)
        ecu_spec1.add_sending_actions(150, 1.5, can_registration.CAN_TEST_MSG, "TEST STRING A", 50)        
        ecu_spec2 = RegularECUSpec(["Test_ECU_2"], 200, 200)     
        ecu_spec3 = SimpleECUSpec(["Test_ECU_3"], 200, 200)       
        
        # Generate random settings in ECUs: EXPECTED VALUES
        for ky in self._av_timing_settings:            
            for ecu_spec in [ecu_spec1 , ecu_spec2 , ecu_spec3]:
                val = random.random()    
                
                # use the constant value else use the function
                if val > 0.5:                            
                    if ecu_spec == ecu_spec1: test_dict["Test_ECU_1"][ky] = val
                    if ecu_spec == ecu_spec2: test_dict["Test_ECU_2"][ky] = val
                    if ecu_spec == ecu_spec3: test_dict["Test_ECU_3"][ky] = val    
                    ecu_spec.set_ecu_setting(ky, val)
                else:
                    if ecu_spec == ecu_spec1: test_dict["Test_ECU_1"][ky] = "FUNCTION"
                    if ecu_spec == ecu_spec2: test_dict["Test_ECU_2"][ky] = "FUNCTION"
                    if ecu_spec == ecu_spec3: test_dict["Test_ECU_3"][ky] = "FUNCTION"  
    
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
                
        # Check if all ECU settings were actually set correctly  
        for ecu in self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3:
             
            # expect a function
            if test_dict[ecu.ecu_id]['t_reg_msg_hash'] == "FUNCTION" and not hasattr(ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG, '__call__'): assert_true(False)
            if test_dict[ecu.ecu_id]['t_reg_msg_outter_enc'] == "FUNCTION" and not hasattr(ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_OUTTER, '__call__'): assert_true(False)
            if test_dict[ecu.ecu_id]['t_conf_msg_dec_time'] == "FUNCTION" and not hasattr(ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_DEC_CONF_MSG, '__call__'): assert_true(False)
            if test_dict[ecu.ecu_id]['t_adv_msg_secmodcert_enc'] == "FUNCTION" and not hasattr(ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ADV_SEC_MOD_CERT_VAL, '__call__'): assert_true(False)
            if test_dict[ecu.ecu_id]['t_reg_msg_sym_keygen'] == "FUNCTION" and not hasattr(ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY, '__call__'): assert_true(False)
            if test_dict[ecu.ecu_id]['t_reg_msg_inner_enc'] == "FUNCTION" and not hasattr(ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_INNER, '__call__'): assert_true(False)


            if test_dict[ecu.ecu_id]['t_reg_msg_hash'] != "FUNCTION" and ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_HASH_REG_MSG != test_dict[ecu.ecu_id]['t_reg_msg_hash']: assert_true(False)
            if test_dict[ecu.ecu_id]['t_reg_msg_outter_enc'] != "FUNCTION" and ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_OUTTER != test_dict[ecu.ecu_id]['t_reg_msg_outter_enc']: assert_true(False)
            if test_dict[ecu.ecu_id]['t_conf_msg_dec_time'] != "FUNCTION" and ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_DEC_CONF_MSG != test_dict[ecu.ecu_id]['t_conf_msg_dec_time']: assert_true(False)
            if test_dict[ecu.ecu_id]['t_adv_msg_secmodcert_enc'] != "FUNCTION" and ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ADV_SEC_MOD_CERT_VAL != test_dict[ecu.ecu_id]['t_adv_msg_secmodcert_enc']: assert_true(False)
            if test_dict[ecu.ecu_id]['t_reg_msg_sym_keygen'] != "FUNCTION" and ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY != test_dict[ecu.ecu_id]['t_reg_msg_sym_keygen']:assert_true(False)
            if test_dict[ecu.ecu_id]['t_reg_msg_inner_enc'] != "FUNCTION" and ecu.ecuSW.comm_mod.authenticator.SCCM_ECU_ENC_REG_MSG_INNER != test_dict[ecu.ecu_id]['t_reg_msg_inner_enc']: assert_true(False) 

        
        assert_true(True)

    def test_fixed_timeout_used(self):
        ''' this test checks if all timing settings are connected properly
            Expected behaviour:
            if the timing parameter was set to a random fixed variable a random
            fixed variable will be used for timeout ''' 
        # DISABLED!
        
        
        # Prepare
        api.build_simulation(self.env)
        self._init_part()           
        test_dict = {}
        test_dict["Test_ECU_1"] = {}
        test_dict["Test_ECU_2"] = {}
        test_dict["Test_ECU_3"] = {}
        ecu_spec1 = RegularECUSpec(["Test_ECU_1"], 200, 200)
        ecu_spec1.add_sending_actions(150, 1.5, can_registration.CAN_TEST_MSG, "TEST STRING A", 50)        
        ecu_spec2 = RegularECUSpec(["Test_ECU_2"], 200, 200)     
        ecu_spec3 = SimpleECUSpec(["Test_ECU_3"], 200, 200)       
        
        # Generate random settings in ECUs: EXPECTED VALUES
        for ky in self._av_timing_settings:            
            for ecu_spec in [ecu_spec1 , ecu_spec2 , ecu_spec3]:
                val = random.random()    
                                          
                if ecu_spec == ecu_spec1: test_dict["Test_ECU_1"][ky] = val
                if ecu_spec == ecu_spec2: test_dict["Test_ECU_2"][ky] = val
                if ecu_spec == ecu_spec3: test_dict["Test_ECU_3"][ky] = val    
                ecu_spec.set_ecu_setting(ky, val)
                    
        # Apply those fixed value settings
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
        self._run_part()
        
        # Check if the simulation used the right timeouts while running
        for ecu in self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3:
             
            if G().used_timeouts[ecu.ecu_id]["['StdAuthentor', 'SCCM_ECU_HASH_REG_MSG']"] != test_dict[ecu.ecu_id]['t_reg_msg_hash']: assert_true(False)
            if G().used_timeouts[ecu.ecu_id]["['StdAuthentor', 'SCCM_ECU_ENC_REG_MSG_OUTTER']"] != test_dict[ecu.ecu_id]['t_reg_msg_outter_enc']: assert_true(False)            
            if G().used_timeouts[ecu.ecu_id]["['StdAuthentor', 'SCCM_ECU_DEC_CONF_MSG']"] != test_dict[ecu.ecu_id]['t_conf_msg_dec_time']: assert_true(False)
            if G().used_timeouts[ecu.ecu_id]["['StdAuthentor', 'SCCM_ECU_ADV_SEC_MOD_CERT_VAL']"] != test_dict[ecu.ecu_id]['t_adv_msg_secmodcert_enc']: assert_true(False)
            if G().used_timeouts[ecu.ecu_id]["['StdAuthentor', 'SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY']"] != test_dict[ecu.ecu_id]['t_reg_msg_sym_keygen']: assert_true(False)
            if G().used_timeouts[ecu.ecu_id]["['StdAuthentor', 'SCCM_ECU_ENC_REG_MSG_INNER']"] != test_dict[ecu.ecu_id]['t_reg_msg_inner_enc']: assert_true(False)
        
        assert_true(True)
         
    def test_timeout_t_normal_msg_dec(self):
        '''
        coresponding global SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY
        
        fixed values for this timeout were already tested
        this test checks the timeout of a normal message decryption.
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY
        # Influencing parameters:      
            - size of the message that was received
            - Algorithm set for the session key
            - Keylength used in the session key
            - library used for the session key
           
        
        A message with 167 is sent. After being encrypted with the given config it has a encrypted size. The message
        with this size is then decrypted. The time needed to do that is the expected time
            
        '''
        
        
        
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_HW', validity=1000))  
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
                
        i = 1
        for test in test_scenarios:
            print("Scenario %s: %s - %s , len: %s, lib: %s" % (i, test.algo, test.mode, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            
            # expected
            enc_size = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'ENCRYPTION')
            test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='DECRYPTION', alg_mode=test.mode, keylen=test.key_len, alg=test.algo, data_size=enc_size)
            
            # actual
            # SET ECUS
            # set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)  

            # SET SEC MOD
            # session key specification   
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_enc_alg', EnumTrafor().to_enum(test.algo))
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_enc_keylen', EnumTrafor().to_enum(test.key_len))
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_enc_alg_mode', EnumTrafor().to_enum(test.mode))
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_validity', test.validity)
            
            
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=test.lib)
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_3']["['StdAuthorize', 'SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)

    def test_timeout_t_normal_msg_enc(self):
        '''
        coresponding global SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY
        
        fixed values for this timeout were already tested
        this test checks the timeout of a normal message encryption.
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY
        # Influencing parameters:      
            - size of the message that needs to be sent
            - Algorithm set for the session key
            - Keylength used in the session key
            - library used for the session key
           
        
        A message with 167 is sent. After being encrypted with the given config it has a encrypted size. The message
        with this size is then decrypted. The time needed to do that is the expected time
            
        '''
        # DISABLED
        
        
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_HW', validity=1000))  
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
                
        i = 1
        print("/n")
        for test in test_scenarios:
            print("Scenario %s: %s - %s , len: %s, lib: %s" % (i, test.algo, test.mode, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            
            # expected
            test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='ENCRYPTION', alg_mode=test.mode, keylen=test.key_len, alg=test.algo, data_size=test.msg_size)
            
            # actual
            # SET ECUS
            # set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)  

            # SET SEC MOD
            # session key specification   
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_enc_alg', EnumTrafor().to_enum(test.algo))
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_enc_keylen', EnumTrafor().to_enum(test.key_len))
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_enc_alg_mode', EnumTrafor().to_enum(test.mode))
            ecu_spec.set_ecu_setting('p_str_auth_ses_key_validity', test.validity)
            
            
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=test.lib)
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthorize', 'SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_timeout_t_adv_msg_secmodcert_enc(self):
        '''
        coresponding global SCCM_ECU_ADV_SEC_MOD_CERT_VAL
        
        time to receive the security module certificate and to verify it
        
        fixed values for this timeout were already tested
        this test checks the timeout of a normal message encryption.
        if it has the expected value: so certain digit
        
        # Corresponding project value: 
        # Influencing parameters:    
            - hashing mechanism of the sec module certificate
            - encryption mechanism  of the sec module certificate
            - Keylength of encryption mechansim of the sec module certificate
            - number of Certification Authorities
            - size of the signed certificate
            - size of the unsigned certificate
        '''
        # DISABLED
        
        
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        unsigned_size = 1500  # vs. signed size = test.msg_size
        
        # vary all parameters from above
        # Cryptolib - RSA
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='MD5', lib='Crypto_Lib_SW', exp=5))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='MD5', lib='Crypto_Lib_SW', exp=5))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=2048, hash_mech='MD5', lib='Crypto_Lib_SW', exp=5))
          
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='MD5', lib='Crypto_Lib_SW', exp=17))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='MD5', lib='Crypto_Lib_SW', exp=17))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=2048, hash_mech='MD5', lib='Crypto_Lib_SW', exp=17))
          
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='MD5', lib='Crypto_Lib_SW', exp=257))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='MD5', lib='Crypto_Lib_SW', exp=257))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=2048, hash_mech='MD5', lib='Crypto_Lib_SW', exp=257))
          
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='MD5', lib='Crypto_Lib_SW', exp=65537))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='MD5', lib='Crypto_Lib_SW', exp=65537))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=2048, hash_mech='MD5', lib='Crypto_Lib_SW', exp=65537))
         
        # Cryptolib - ECC        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=192, hash_mech='MD5', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=256, hash_mech='MD5', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=384, hash_mech='MD5', lib='Crypto_Lib_SW'))
        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=192, hash_mech='SHA1', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=256, hash_mech='SHA1', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=384, hash_mech='SHA1', lib='Crypto_Lib_SW'))

        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=192, hash_mech='SHA256', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=256, hash_mech='SHA256', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=384, hash_mech='SHA256', lib='Crypto_Lib_SW'))

               
        # CyaSSL - RSA
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='MD5', lib='CyaSSL', exp=3))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='MD5', lib='CyaSSL', exp=3))
            
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA1', lib='CyaSSL', exp=3))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA1', lib='CyaSSL', exp=3))
        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA256', lib='CyaSSL', exp=3))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA256', lib='CyaSSL', exp=3))
             
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='MD5', lib='CyaSSL', exp=5))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='MD5', lib='CyaSSL', exp=5))
           
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA1', lib='CyaSSL', exp=5))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA1', lib='CyaSSL', exp=5))
       
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA256', lib='CyaSSL', exp=5))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA256', lib='CyaSSL', exp=5))
        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='MD5', lib='CyaSSL', exp=17))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='MD5', lib='CyaSSL', exp=17))
           
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA1', lib='CyaSSL', exp=17))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA1', lib='CyaSSL', exp=17))
        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA256', lib='CyaSSL', exp=17))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA256', lib='CyaSSL', exp=17))
       
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='MD5', lib='CyaSSL', exp=257))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='MD5', lib='CyaSSL', exp=257))
            
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA1', lib='CyaSSL', exp=257))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA1', lib='CyaSSL', exp=257))
        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA256', lib='CyaSSL', exp=257))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA256', lib='CyaSSL', exp=257))
        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='MD5', lib='CyaSSL', exp=65537))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='MD5', lib='CyaSSL', exp=65537))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=2048, hash_mech='MD5', lib='CyaSSL', exp=65537))      
            
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA1', lib='CyaSSL', exp=65537))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA1', lib='CyaSSL', exp=65537))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=2048, hash_mech='SHA1', lib='CyaSSL', exp=65537))      
        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=512, hash_mech='SHA256', lib='CyaSSL', exp=65537))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=1024, hash_mech='SHA256', lib='CyaSSL', exp=65537))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="RSA", key_len=2048, hash_mech='SHA256', lib='CyaSSL', exp=65537))  
               
        # CyaSSL - ECC        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=256, hash_mech='MD5', lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=384, hash_mech='MD5', lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=521, hash_mech='MD5', lib='CyaSSL'))
          
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=256, hash_mech='SHA1', lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=384, hash_mech='SHA1', lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=521, hash_mech='SHA1', lib='CyaSSL'))
        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=256, hash_mech='SHA256', lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=384, hash_mech='SHA256', lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=521, hash_mech='SHA256', lib='CyaSSL'))  
             
        i = 1
        print("/n")
        for test in test_scenarios:
            if test.algo == "RSA":  print(r"Scenario %s/%s: %s - exp %s , len: %s, lib: %s, hash: %s" % (i, len(test_scenarios), test.algo, test.exponent, test.key_len, test.lib, test.hash_mech)); 
            else:                   print(r"Scenario %s/%s: %s, len: %s, lib: %s, hash: %s" % (i, len(test_scenarios), test.algo, test.key_len, test.lib, test.hash_mech)); 
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            
            # expected time to verify: 
            # CyaSSL         RSA: Verify: create_comparehash + decrypt + compare hash(neglectable) == encryption time as this is the inverse operation
            # CyaSSL         ECC: Verify: verify_hash operation
            # Crypto_Lib_SW  RSA: Verify: verify operation
            # Crypto_Lib_SW  ECC: Verify: verify operation
            if test.algo == "RSA" and test.lib == "CyaSSL":  
                t_hash = TimingDBMap().lookup_interpol(lib=test.lib, mode='HASH', alg=test.hash_mech, data_size=unsigned_size)
                t_enc = TimingDBMap().lookup_interpol(lib=test.lib, exp=test.exponent, mode='ENCRYPTION', keylen=test.key_len, alg=test.algo, data_size=test.msg_size)
                test.expected = test.ca_len * (t_enc + t_hash)            
            elif test.algo == "RSA":  
                t_enc = TimingDBMap().lookup_interpol(lib=test.lib, exp=test.exponent, mode='VERIFY', keylen=test.key_len, alg=test.algo, data_size=unsigned_size)
                test.expected = test.ca_len * t_enc                
            elif test.algo == "ECC":  
                t_enc = TimingDBMap().lookup_interpol(lib=test.lib, mode='VERIFY', param_len=test.key_len, alg=test.algo, data_size=unsigned_size)
                test.expected = test.ca_len * t_enc
            
            i += 1
            
            # actual
            # SET ECUS
            # set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)  

            # SET SEC MOD
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            # size of certificate after the signing operation/ and used encryption mechanisms
            ecu_spec.set_ecu_setting('p_sec_mod_cert_signed_hash_size', test.msg_size) 
            ecu_spec.set_ecu_setting('p_sec_mod_cert_hash_size', unsigned_size) 
            ecu_spec.set_ecu_setting('p_sec_mod_cert_hashing_mech', EnumTrafor().to_enum(test.hash_mech))
            ecu_spec.set_ecu_setting('p_sec_mod_cert_enc_mech', EnumTrafor().to_enum(test.algo))
            ecu_spec.set_ecu_setting('p_sec_mod_cert_enc_mech_option', test.exponent)
            ecu_spec.set_ecu_setting('p_sec_mod_cert_enc_keylen', EnumTrafor().to_enum(test.key_len))
            ecu_spec.set_ecu_setting('p_sec_mod_cert_ca_len', test.ca_len)

            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=test.lib)
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthentor', 'SCCM_ECU_ADV_SEC_MOD_CERT_VAL']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_t_reg_msg_sym_keygen(self):
        '''
        coresponding global SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY
        
        time to generate the symetric ECU Key that will be exchanged
        
        fixed values for this timeout were already tested
        this test checks the timeout of a normal message encryption.
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY
        # Influencing parameters:      
            - Algorithm set for the ECU key
            - Keylength used in the ECU key
            - library used for the ECU key generation

           
        As a response to the ecu advertisement a registration message is sent.
        This message contains a symmetric key that is generated
            
            
        Not measured yet!!!!!!!!
        Todo: Measure and revise this implementation
        '''
        # DISABLED
        

        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", key_len=128, lib='CyaSSL'))
               
        i = 1
        print("/n")
        for test in test_scenarios:
            print("Scenario %s: %s - %s , len: %s, lib: %s" % (i, test.algo, test.mode, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg', test.algo)
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg_mode', test.mode)
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_keylen', test.key_len)
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg', test.algo)
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg_mode', test.mode)
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_keylen', test.key_len)
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg', test.algo)
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg_mode', test.mode)
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_keylen', test.key_len)
            
            # expected
            test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='KEYGEN', keylen=test.key_len, alg=test.algo)
            
            # actual
            # SET ECUS
            # set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)

            # SET SEC MOD
            # session key specification   
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
                        
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag='CyaSSL')
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthorize', 'SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_t_reg_msg_inner_enc(self):
        '''
        coresponding global SCCM_ECU_ENC_REG_MSG_INNER
        
        As a response to the ecu advertisement a registration message is sent.
        This message encrypts in its first step [sec_id, self.sym_key, nonce, timestamp]
        the tested time is the time needed for that encryption
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_ECU_ENC_REG_MSG_INNER
        # Influencing parameters:      
            - Algorithm set for the inner encryption
            - Keylength used in the inner encryption
            - library used in the inner encryption
            - size of the inner part to encrypt
           
        

        Operation: public_encryption (Note: private encrypt == SIGN, public decrpt = VERIFY)
        '''
        # DISABLED
        
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        
        # CyaSSL RSA: PublicEncrypt
        # CyaSSL ECC: PublicEncrypt
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=3, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=3, key_len=1024, lib='CyaSSL'))
         
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=5, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=5, key_len=1024, lib='CyaSSL'))
         
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=17, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=17, key_len=1024, lib='CyaSSL'))
         
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=257, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=257, key_len=1024, lib='CyaSSL'))
         
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=65537, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=65537, key_len=1024, lib='CyaSSL'))        
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=65537, key_len=2048, lib='CyaSSL'))
               
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=256, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=384, lib='CyaSSL'))        
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=521, lib='CyaSSL'))
               
        i = 1
        for test in test_scenarios:
            print("Scenario %s - exp %s: %s , len: %s, lib: %s" % (i, test.algo, test.exponent, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
            self.ecu_spec_2.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
            self.ecu_spec_3.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
                        
            # expected
            if test.algo == "ECC":
                test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='ENCRYPTION', param_len=test.key_len, alg=test.algo, data_size=test.msg_size)
            if test.algo == "RSA":
                test.expected = TimingDBMap().lookup_interpol(lib=test.lib, exp=test.exponent, mode='ENCRYPTION', keylen=test.key_len, alg=test.algo, data_size=test.msg_size)
            
            # actual
            # SET ECUS: set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)

            # SET SEC MOD
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
                                  
            # Inner encryption specification
            ecu_spec.set_ecu_setting('p_reg_msg_inner_content_size', test.msg_size)            
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method', EnumTrafor().to_enum(test.algo))
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method_option', test.exponent)
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_keylen', EnumTrafor().to_enum(test.key_len))
                                    
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag='CyaSSL')
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthentor', 'SCCM_ECU_ENC_REG_MSG_INNER']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_t_reg_msg_hash(self):
        '''
        coresponding global SCCM_ECU_HASH_REG_MSG
        
        when generating the registration message it takes a certain time
        to hash [sec_id, self.sym_key, nonce, timestamp]. If this time
        is set correctly is tested in this method
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_ECU_HASH_REG_MSG
        # Influencing parameters:      
            - Algorithm used for hashing
            - library used for hashing
            - size of the inner part to hash
           
        Operation: hashing
        '''
        # DISABLED
        

        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        
        test_scenarios.append(TestConfigComponent(msg_size=338, hash_mech="MD5", lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=338, hash_mech="SHA1", lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=338, hash_mech="SHA256", lib='CyaSSL'))
         
        test_scenarios.append(TestConfigComponent(msg_size=338, hash_mech="MD5", lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=338, hash_mech="SHA1", lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=338, hash_mech="SHA256", lib='Crypto_Lib_SW'))
               
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s : %s ,lib: %s" % (i, test.hash_mech, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
            self.ecu_spec_2.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
            self.ecu_spec_3.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
                        
            # expected
            test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='HASH', alg=test.hash_mech, data_size=test.msg_size)

            # actual
            # SET ECUS: set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)

            # SET SEC MOD
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
                                  
            # Inner encryption specification
            ecu_spec.set_ecu_setting('p_reg_msg_inner_content_size', test.msg_size)            
            ecu_spec.set_ecu_setting('p_reg_msg_hash_alg', EnumTrafor().to_enum(test.hash_mech))
            
            # DUMMY
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method', EnumTrafor().to_enum("RSA"))
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method_option', 3)
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_keylen', EnumTrafor().to_enum(512)) 
                                                              
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag='CyaSSL')
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthentor', 'SCCM_ECU_HASH_REG_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_t_reg_msg_outter_enc(self):
        '''
        coresponding global SCCM_ECU_ENC_REG_MSG_OUTTER
        
        As a response to the ecu advertisement a registration message is sent.
        This message encrypts in its second step the hash of ([sec_id, self.sym_key, nonce, timestamp])
        the tested time is the time needed for that encryption
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_ECU_ENC_REG_MSG_OUTTER
        # Influencing parameters:      
            - Algorithm set for the outter encryption
            - Keylength used in the outter encryption
            - library used in the outter encryption
            - size of the outter part to encrypt
           
        Operation: private encrypt == SIGN
        '''
        
        # DISABLED
        

        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        
        # CryptoLib: RSA - Sign   
#         test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=5, key_len=512, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=5, key_len=1024, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=5, key_len=2048, lib='Crypto_Lib_SW'))
        
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=17, key_len=512, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=17, key_len=1024, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=17, key_len=2048, lib='Crypto_Lib_SW'))
        
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=257, key_len=512, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=257, key_len=1024, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=257, key_len=2048, lib='Crypto_Lib_SW'))
        
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=65537, key_len=512, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=65537, key_len=1024, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=65537, key_len=2048, lib='Crypto_Lib_SW'))
        
        # CryptoLib: ECC - Sign
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=192, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=256, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=384, lib='Crypto_Lib_SW'))
        
        # CyaSLL: RSA - Sign = DECRYPTION as this is the inverse operation     
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=3, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=3, key_len=1024, lib='CyaSSL'))
         
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=5, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=5, key_len=1024, lib='CyaSSL'))
          
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=17, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=17, key_len=1024, lib='CyaSSL'))
          
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=257, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=257, key_len=1024, lib='CyaSSL'))
          
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=65537, key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=65537, key_len=1024, lib='CyaSSL'))        
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=65537, key_len=2048, lib='CyaSSL'))
                        
        # CyaSLL: ECC - Sign Hash       
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=256, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=384, lib='CyaSSL'))        
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=521, lib='CyaSSL'))
               
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s - exp %s: %s , len: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.exponent, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
            self.ecu_spec_2.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
            self.ecu_spec_3.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
                        
            # expected
            # CryptoLib: RSA - Sign
            # CryptoLib: ECC - Sign
            # CyaSLL: RSA - Sign = DECRYPTION as this is the inverse operation
            # CyaSLL: ECC - Sign                        
            if test.algo == "ECC":
                test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='SIGN', param_len=test.key_len, alg=test.algo, data_size=test.msg_size)
            if test.algo == "RSA" and test.lib == "CyaSSL":
                test.expected = TimingDBMap().lookup_interpol(lib=test.lib, exp=test.exponent, mode='DECRYPTION', keylen=test.key_len, alg=test.algo, data_size=test.msg_size)
            if test.algo == "RSA" and test.lib == "Crypto_Lib_SW":
                test.expected = TimingDBMap().lookup_interpol(lib=test.lib, exp=test.exponent, mode='SIGN', keylen=test.key_len, alg=test.algo, data_size=test.msg_size)
            
            # actual
            # SET ECUS: set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)

            # SET SEC MOD
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
                                  
            # Inner encryption specification
            ecu_spec.set_ecu_setting('p_reg_msg_outter_hash_size', test.msg_size)  # hash to sign                  
            ecu_spec.set_ecu_setting('p_reg_msg_outter_enc_alg', EnumTrafor().to_enum(test.algo))
            ecu_spec.set_ecu_setting('p_reg_msg_outter_enc_keylen', EnumTrafor().to_enum(test.key_len))
            
            ecu_spec.set_ecu_setting('p_reg_msg_outter_enc_alg_option', test.exponent)
                           
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag='CyaSSL')
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthentor', 'SCCM_ECU_ENC_REG_MSG_OUTTER']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)

    def test_t_conf_msg_dec_time(self):
        '''
        coresponding global SCCM_ECU_DEC_CONF_MSG
        
        Once the ecu authentication was successful a confirmation message is received.
        The time it takes to decrypt the received confirmation message is tested
        here.
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_ECU_DEC_CONF_MSG
        # Influencing parameters:      
            - Algorithm (and mode) set for the decryption: Algorithm for symmetric ECU Keys
            - Keylength used in the decryption
            - library used in the decryption
            - size of the confirmation message
           
        Operation: symmetric decryption
        '''

        # DISABLED
        
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_HW', validity=1000))  
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
                
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s: %s - %s , len: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
            self.ecu_spec_2.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
            self.ecu_spec_3.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)
            
            # ECU Key encryption mechanism
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            
            # expected
            test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='DECRYPTION', alg_mode=test.mode, keylen=test.key_len, alg=test.algo, data_size=test.msg_size)
            
            # actual
            # SET ECUS: set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)

            # SET SEC MOD
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
                                  
            ecu_spec.set_ecu_setting('p_conf_msg_cipher_size', test.msg_size)  # size of confirmation message              
            
                                       
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=test.lib)
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthentor', 'SCCM_ECU_DEC_CONF_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
     
    def test_t_req_msg_max_timeout(self):
        '''
        coresponding global SCCM_MAX_WAIT_TIMEOUT
        
        If a stream request was sent and no response was received within a certain 
        time 't_req_msg_max_timeout'. Then the request is aborted
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_MAX_WAIT_TIMEOUT
        # Influencing parameters:      
            - fixed value
           
        Operation: simply wait
        '''
        
        

        # Preprocess
        self._init_part()            
        self._ecu_spec_creation()

        # expected
        expected = 0.01

        # process
        self.ecu_spec_1.set_ecu_setting('t_req_msg_max_timeout', expected)                
        self._ecu_spec_application()
        self._ecu_spec_timing_application()        
        self._sec_mod_creation_part()       
        self._bus_creation_part()
        self._ecu_to_sec_mod_part()        
        self._set_streams_part()
        self._run_part()
        
        # actual
        actual = G().used_timeouts['Test_ECU_1']["['SecureCommModule', 't_req_msg_max_timeout']"]

        # Compare
        assert actual == expected
         
    def test_t_req_msg_stream_enc(self):
        '''
        coresponding global SCCM_STREAM_ENC_REQ_MSG
        
        If a ECU wants to send a message it sends a request message
        This message is encrypted using symmetric encryption. The time
        this encryption takes is tested here
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_STREAM_ENC_REQ_MSG
        # Influencing parameters:      
            - Algorithm (and mode) set for the decryption 
            - Keylength used in the decryption
            - library used in the decryption
            - size of the request message
           
        Operation: symmetric encryption
        '''
        
        
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_HW', validity=1000))  
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
                
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s: %s - %s , len: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            
            # ECU Key encryption mechanism
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            # expected
            test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='ENCRYPTION', alg_mode=test.mode, keylen=test.key_len, alg=test.algo, data_size=test.msg_size)
            
            # actual
            # SET ECUS: set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)

            # SET SEC MOD
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
                                  
            ecu_spec.set_ecu_setting('p_req_msg_content_size', test.msg_size)  # size of the request message             
                
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=test.lib)
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthorize', 'SCCM_STREAM_ENC_REQ_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)

    def test_t_deny_msg_stream_dec(self):
        '''
        coresponding global SCCM_STREAM_DEC_DENY_MSG
        
        If a ECU is not allowed to send a stream but asks 
        for it it will receive a deny message. The time to
        decrypt the received deny message is tested here
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_STREAM_DEC_DENY_MSG
        # Influencing parameters:      
            - Algorithm (and mode) set for the decryption 
            - Keylength used in the decryption
            - library used in the decryption
            - size of the request message
           
        Operation: symmetric decryption
        '''
        

        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_HW', validity=1000))  
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
                
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s: %s - %s , len: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            
            # ECU Key encryption mechanism
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            
            # expected
            test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='DECRYPTION', alg_mode=test.mode, keylen=test.key_len, alg=test.algo, data_size=test.msg_size)
            
            # actual
            # SET ECUS: set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)

            # SET SEC MOD
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
                                  
            ecu_spec.set_ecu_setting('p_grant_msg_cipher_size', test.msg_size)  # size of the deny message             
                
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=test.lib)
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
             
            stream_1 = MessageStream('Test_ECU_4', ['Test_ECU_2', 'Test_ECU_3'], can_registration.CAN_TEST_MSG, float('inf'), 0, float('inf'))
            api.add_allowed_stream(self.env, 'SEC 1', stream_1)
            api.autoset_gateway_filters(self.env, 'SEC 1')
                 
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthorize', 'SCCM_STREAM_DEC_DENY_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
        
    def test_t_grant_msg_stream_dec(self):
        '''
        coresponding global SCCM_STREAM_DEC_GRANT_MSG
        
        If a ECU is allowed to send a stream ans asks 
        for it it will receive a grant message. The time to
        decrypt the received message is tested here
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SCCM_STREAM_DEC_GRANT_MSG
        # Influencing parameters:      
            - Algorithm (and mode) set for the decryption 
            - Keylength used in the decryption
            - library used in the decryption
            - size of the request message
           
        Operation: symmetric decryption
        '''
        
        
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CCM', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_HW', validity=1000))  
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CBC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='ECB', key_len=256, lib='Crypto_Lib_SW', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=128, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=192, lib='Crypto_Lib_SW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=167, algo="AES", mode='CMAC', key_len=256, lib='Crypto_Lib_SW', validity=1000))
                
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s: %s - %s , len: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            
            # ECU Key encryption mechanism
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_1.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_2.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_alg_mode', EnumTrafor().to_enum(test.mode))
            self.ecu_spec_3.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))
            
            # expected
            test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='DECRYPTION', alg_mode=test.mode, keylen=test.key_len, alg=test.algo, data_size=test.msg_size)
            
            # actual
            # SET ECUS: set the library
            self._ecu_spec_application()
            t_set2 = TimingFunctionSet() 
            ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=test.lib)
            for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
                t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
                api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2)

            # SET SEC MOD
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
                                  
            ecu_spec.set_ecu_setting('p_grant_msg_cipher_size', test.msg_size)  # size of the grant message             
                
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            
            # process    
            t_set = TimingFunctionSet()
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=test.lib)
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()                 
            self._run_part()
            
            # expected
            expected = test.expected
            
            # actual
            actual = G().used_timeouts['Test_ECU_1']["['StdAuthorize', 'SCCM_STREAM_DEC_GRANT_MSG']"]

            if expected != actual:
                print("Actual was %s while expected %s" % (actual, expected))
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
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








