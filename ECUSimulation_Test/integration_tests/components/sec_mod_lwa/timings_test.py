'''
Testing the timeout values
If they were accessed correctly and if they have
the expected values depending on the set algorithms
'''
import logging
import os
import random

from astropy.io.ascii.tests.common import assert_true
import numpy
from numpy.core.defchararray import isnumeric

from api.core.api_core import APICore, TimingFunctionSet
from api.core.component_specs import RegularECUSpec, SimpleECUSpec, \
    SimpleBusSpec
import api.ecu_sim_api as api
from components.base.gateways.impl_can_gateway import CANGateway
from components.security.communication.stream import MessageStream
from components.security.ecu.types.impl_ecu_secure import     StdSecurECUTimingFunctions
from components.security.ecu.types.impl_sec_mod_lwa import StdSecurLwSecModTimingFunctions, \
    SecLwAuthSecurityModule
from components.security.encryption.encryption_tools import EncryptionSize
from config import can_registration
from config.timing_db_admin import TimingDBMap
from enums.sec_cfg_enum import CAEnum, AsymAuthMechEnum, AuKeyLengthEnum, \
    EnumTrafor
from tools.general import General as G

import unittest2 as unittest
from tools.ecu_logging import ECULogger


class SecLwAuthSecurityModuleTimingIntegrationTest(unittest.TestCase):
    '''
        Classes under test: SecLwAuthSecurityModule, StdSecurityModuleAppLayer
    
        This class tests all timings in the following way:
        It generates a certain test environment and runs it
        for x seconds. Depending on the settings of the environment
        certain outcome timing values are expected.  
    '''

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
        return
        # Prepare
        api.build_simulation(self.env)
        self._init_part()           
        test_dict = {}
        self._ecu_creation_part()    
        ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)  
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)  
        
        # Generate random settings in Sec Module: EXPECTED VALUES
        const_vals = ['t_ecu_auth_trigger_process', 't_ecu_auth_trigger_intervall', 't_ecu_auth_reg_msg_comp_hash_process' ]
        for ky in self._av_timing_settings: 
            val = random.random()    
            
            # use the constant value else use the function
            if val > 0.5 or ky in const_vals:                                            
                test_dict[ky] = val 
                ecu_spec.set_ecu_setting(ky, val)
            else:
                test_dict[ky] = "FUNCTION"
    
        # Apply those settings       
        self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]
        self._sec_mod_timing_set()       
        self._bus_creation_part()
        self._ecu_to_sec_mod_part()        
        self._set_streams_part()        
        api.build_simulation(self.env)
                
        # Check if all SEC MOD settings were actually set correctly  
        # expect a function
        if test_dict['t_ecu_auth_trigger_process'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_TRIGGER_AUTH_PROCESS_T, '__call__'): assert_true(False)
        if test_dict['t_ecu_auth_trigger_intervall'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.SSMA_ECU_AUTH_INTERVAL, '__call__'): assert_true(False)
        if test_dict['t_ecu_auth_reg_msg_create_comp_hash'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_CREATE_CMP_HASH_REG_MSG, '__call__'): assert_true(False)
        if test_dict['t_ecu_auth_reg_msg_validate_cert'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_VALID_CERT_REG_MSG, '__call__'): assert_true(False)
        if test_dict['t_ecu_auth_reg_msg_comp_hash_process'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_HASH_CMPR_REG_MSG, '__call__'): assert_true(False)        
        if test_dict['t_ecu_auth_reg_msg_inner_dec'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_DECR_INNER_REG_MSG, '__call__'): assert_true(False)        
        if test_dict['t_ecu_auth_reg_msg_outter_dec'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_DECR_OUTTER_REG_MSG, '__call__'): assert_true(False)        
        if test_dict['t_ecu_auth_conf_msg_enc'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_ENCR_CONF_MSG_ECU_KEY, '__call__'): assert_true(False)        
        if test_dict['t_str_auth_decr_req_msg'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.stream_auth.SSMA_STREAM_REQ_INI_DECR, '__call__'): assert_true(False)        
        if test_dict['t_str_auth_enc_deny_msg'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.stream_auth.SSMA_STREAM_ENC_DENY_MSG, '__call__'): assert_true(False)        
        if test_dict['t_str_auth_keygen_grant_msg'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.stream_auth.SSMA_SESS_KEYGEN_GRANT_MSG, '__call__'): assert_true(False)        
        if test_dict['t_str_auth_enc_grant_msg'] == "FUNCTION" and not hasattr(self.sec_mod.ecuSW.app_lay.stream_auth.SSMA_STREAM_ENC_GRANT_MSG, '__call__'): assert_true(False)

        if test_dict['t_ecu_auth_trigger_process'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_TRIGGER_AUTH_PROCESS_T != test_dict['t_ecu_auth_trigger_process']: assert_true(False)
        if test_dict['t_ecu_auth_trigger_intervall'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.SSMA_ECU_AUTH_INTERVAL != test_dict['t_ecu_auth_trigger_intervall']: assert_true(False)
        if test_dict['t_ecu_auth_reg_msg_create_comp_hash'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_CREATE_CMP_HASH_REG_MSG != test_dict['t_ecu_auth_reg_msg_create_comp_hash']: assert_true(False)
        if test_dict['t_ecu_auth_reg_msg_validate_cert'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_VALID_CERT_REG_MSG != test_dict['t_ecu_auth_reg_msg_validate_cert']: assert_true(False)
        if test_dict['t_ecu_auth_reg_msg_comp_hash_process'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_HASH_CMPR_REG_MSG != test_dict['t_ecu_auth_reg_msg_comp_hash_process']:assert_true(False)        
        if test_dict['t_ecu_auth_reg_msg_inner_dec'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_DECR_INNER_REG_MSG != test_dict['t_ecu_auth_reg_msg_inner_dec']: assert_true(False)         
        if test_dict['t_ecu_auth_reg_msg_outter_dec'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_DECR_OUTTER_REG_MSG != test_dict['t_ecu_auth_reg_msg_outter_dec']: assert_true(False)        
        if test_dict['t_ecu_auth_conf_msg_enc'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.ecu_auth.SSMA_ENCR_CONF_MSG_ECU_KEY != test_dict['t_ecu_auth_conf_msg_enc']: assert_true(False)        
        if test_dict['t_str_auth_decr_req_msg'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.stream_auth.SSMA_STREAM_REQ_INI_DECR != test_dict['t_str_auth_decr_req_msg']: assert_true(False)        
        if test_dict['t_str_auth_enc_deny_msg'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.stream_auth.SSMA_STREAM_ENC_DENY_MSG != test_dict['t_str_auth_enc_deny_msg']: assert_true(False)    
        if test_dict['t_str_auth_keygen_grant_msg'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.stream_auth.SSMA_SESS_KEYGEN_GRANT_MSG != test_dict['t_str_auth_keygen_grant_msg']:assert_true(False)
        
        if test_dict['t_str_auth_enc_grant_msg'] != "FUNCTION" and self.sec_mod.ecuSW.app_lay.stream_auth.SSMA_STREAM_ENC_GRANT_MSG != test_dict['t_str_auth_enc_grant_msg']: assert_true(False) 

        assert_true(True)
     
    def test_t_ecu_auth_trigger_process(self):        
        '''
        coresponding global SSMA_TRIGGER_AUTH_PROCESS_T
        
        fixed values for this timeout were already tested
        this test checks the timeout of a normal message decryption.
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_TRIGGER_AUTH_PROCESS_T
        # Influencing parameters:      
            - None this is a fixed value
           
        
        This process defines when the ecu authentication process will start. This method tests
        if it really starts then
            
        '''
        return
        # Preprocess
        self._init_part()            
        self._ecu_spec_creation()

        # expected
        expected = 0.5

        # process
        self.ecu_spec_1.set_ecu_setting('t_ecu_auth_trigger_process', expected)                
        self._ecu_spec_application()
        self._ecu_spec_timing_application()        
        
        ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)  
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)  
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', expected)  
        self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]        
        self._sec_mod_timing_set()                  
        self._bus_creation_part()
        self._ecu_to_sec_mod_part()        
        self._set_streams_part()
        self._run_part()
        
        # actual
        actual = G().used_timeouts['SEC 1']["['ECUAuthenticator', 'SSMA_TRIGGER_AUTH_PROCESS_T']"]

        # Compare
        assert actual == expected
    
    def test_t_ecu_auth_trigger_intervall(self):
        '''
        coresponding global SSMA_ECU_AUTH_INTERVAL
        
        fixed values for this timeout were already tested
        this test checks the timeout of a normal message decryption.
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_ECU_AUTH_INTERVAL
        # Influencing parameters:      
            - None this is a fixed value
           
        
        This process defines when the ecu authentication process will start. This method tests
        if it really starts in the defined fixed intervals
            
        '''
        return
        # Preprocess
        self._init_part()       
        self._ecu_spec_creation()

        # expected
        interval = 130
        expected = 140

        # process
        self.ecu_spec_1.set_ecu_setting('t_ecu_auth_trigger_process', expected)                
        self._ecu_spec_application()
        self._ecu_spec_timing_application()        
        
        ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)  
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', interval)  
        self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]        
        self._sec_mod_timing_set()                  
        self._bus_creation_part()
        self._ecu_to_sec_mod_part()        
        self._set_streams_part()
        self._run_part()
        
        # actual
        actual = G().noted_ts["['SEC 1', 'TRIGGERED_AUTHENTICATION']"]

        # Compare
        assert actual == expected
    
    def test_t_ecu_auth_reg_msg_validate_cert(self):
        '''
        coresponding global SSMA_VALID_CERT_REG_MSG
        
        time to receive the ECU certificate and to verify it
        
        fixed values for this timeout were already tested
        this test checks the timeout of a normal message encryption.
        if it has the expected value: so certain digit
        
        # Corresponding project value: 
        # Influencing parameters:    
            - hashing mechanism of the ECU certificate
            - encryption mechanism  of the ECU certificate
            - Keylength of encryption mechansim of the ECU certificate
            - number of Certification Authorities
            - size of the signed certificate
            - size of the unsigned certificate
        '''
        return
        
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
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_signed_size', test.msg_size) 
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_unsigned_size', unsigned_size) 
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_hash_mech', EnumTrafor().to_enum(test.hash_mech))
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_mech', EnumTrafor().to_enum(test.algo))
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_mech_option', test.exponent)
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_enc_keylen', EnumTrafor().to_enum(test.key_len))
            ecu_spec.set_ecu_setting('p_ecu_auth_cert_ca_len', test.ca_len)

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
            actual = G().used_timeouts['SEC 1']["['ECUAuthenticator', 'SSMA_VALID_CERT_REG_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_t_ecu_auth_reg_msg_create_comp_hash(self):
        '''
        coresponding global SSMA_CREATE_CMP_HASH_REG_MSG
        
        before being able to compare the hash to the result the hash
        has to be generated  
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_CREATE_CMP_HASH_REG_MSG
        # Influencing parameters:      
            - Algorithm used for hashing
            - library used for hashing
            - size of the inner part to hash
           
        Operation: hashing
        '''
        return
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
            
            # Preprocess
            self._init_part()        
            self._ecu_spec_creation() 
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)            
            sec_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            sec_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            sec_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)

            # SET SEC MOD
            sec_spec.set_ecu_setting('p_reg_msg_inner_content_size', test.msg_size)            
            sec_spec.set_ecu_setting('p_reg_msg_hash_alg', EnumTrafor().to_enum(test.hash_mech))                                                                          
    
            # process   
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', sec_spec)[0]   
            self._sec_mod_timing_set(test.lib)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected
            expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='HASH', alg=test.hash_mech, data_size=test.msg_size)

            # actual
            actual = G().used_timeouts['SEC 1']["['ECUAuthenticator', 'SSMA_CREATE_CMP_HASH_REG_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_t_ecu_auth_reg_msg_inner_dec(self):
        '''
        coresponding global SSMA_DECR_INNER_REG_MSG
        
        As a response to the ecu advertisement a registration message is sent.
        This message encrypts in its first step [sec_id, self.sym_key, nonce, timestamp]
        the tested time is the time needed for the decryption of the encryption of that
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_DECR_INNER_REG_MSG
        # Influencing parameters:      
            - Algorithm set for the inner encryption
            - Keylength used in the inner encryption
            - library used in the inner encryption
            - size of the inner part to encrypt
           
        Operation: private_decryption (Note: private encrypt == SIGN, public decrpt = VERIFY)
        '''
        return
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
               
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=256, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=384, lib='CyaSSL'))        
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="ECC", key_len=521, lib='CyaSSL'))
               
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s - exp %s: %s , len: %s, lib: %s" % (i, test.algo, test.exponent, test.key_len, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation()             
            ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)      
                         
            # expected
            # size to decrypt is the cipher size of the inner content
            cipher_size = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'ENCRYPTION') 
            if test.algo == "ECC":
                expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='DECRYPTION', param_len=test.key_len, alg=test.algo, data_size=cipher_size)
            if test.algo == "RSA":
                expected = TimingDBMap().lookup_interpol(lib=test.lib, exp=test.exponent, mode='DECRYPTION', keylen=test.key_len, alg=test.algo, data_size=cipher_size)
            
            
            # actual - settings
            ecu_spec.set_ecu_setting('p_reg_msg_inner_content_size', test.msg_size)            
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method', EnumTrafor().to_enum(test.algo))
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_method_option', test.exponent)
            ecu_spec.set_ecu_setting('p_reg_msg_inner_enc_keylen', EnumTrafor().to_enum(test.key_len))
               
            # process    
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)                     
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]  
            self._sec_mod_timing_set(test.lib)            
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # actual
            actual = G().used_timeouts['SEC 1']["['ECUAuthenticator', 'SSMA_DECR_INNER_REG_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_t_ecu_auth_reg_msg_outter_dec(self):
        '''
        coresponding global SSMA_DECR_OUTTER_REG_MSG
        
        As a response to the ecu advertisement a registration message is sent.
        This message encrypts in its second step the hash of ([sec_id, self.sym_key, nonce, timestamp])
        the tested time is the time needed for the decryption of its encrypted version
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_DECR_OUTTER_REG_MSG
        # Influencing parameters:      
            - Algorithm set for the outter encryption
            - Keylength used in the outter encryption
            - library used in the outter encryption
            - size of the outter part to encrypt
           
        Operation: public decrypt == VERIFY
        

        '''
        # DISABLED
        return
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []
        
        # CryptoLib: RSA - Sign   
        test_scenarios.append(TestConfigComponent(msg_size=225, algo="RSA", exp=5, key_len=512, lib='Crypto_Lib_SW'))
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

            self.ecu_spec_1.set_ecu_setting('p_reg_msg_sending_size', 100)
            self.ecu_spec_2.set_ecu_setting('p_reg_msg_sending_size', 100)
            self.ecu_spec_3.set_ecu_setting('p_reg_msg_sending_size', 100)
                        
            # expected
            # CryptoLib: RSA - Sign
            # CryptoLib: ECC - Sign
            # CyaSLL: RSA - Sign = DECRYPTION as this is the inverse operation
            # CyaSLL: ECC - Sign                        
            cipher_size = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'SIGN')              
            if test.algo == "ECC":
                expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='VERIFY', param_len=test.key_len, alg=test.algo, data_size=cipher_size)
            if test.algo == "RSA" and test.lib == "CyaSSL":
                expected = TimingDBMap().lookup_interpol(lib=test.lib, exp=test.exponent, mode='ENCRYPTION', keylen=test.key_len, alg=test.algo, data_size=cipher_size)
            if test.algo == "RSA" and test.lib == "Crypto_Lib_SW":
                expected = TimingDBMap().lookup_interpol(lib=test.lib, exp=test.exponent, mode='VERIFY', keylen=test.key_len, alg=test.algo, data_size=cipher_size)
            
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
            ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=test.lib)
            t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
            api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
                        
            # actual
            actual = G().used_timeouts['SEC 1']["['ECUAuthenticator', 'SSMA_DECR_OUTTER_REG_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
        
    def test_t_ecu_auth_conf_msg_enc(self):
        '''
        coresponding global SSMA_ENCR_CONF_MSG_ECU_KEY
        
        Once the ecu authentication was successful a confirmation message is received.
        The time it takes to encrypt the confirmation message is tested
        here.
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_ENCR_CONF_MSG_ECU_KEY
        # Influencing parameters:      
            - Algorithm (and mode) set for the decryption: Algorithm for symmetric ECU Keys
            - Keylength used in the decryption
            - library used in the decryption
            - size of the confirmation message
           
        Operation: symmetric decryption
        '''
        return
        
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
                                  
            ecu_spec.set_ecu_setting('p_ecu_auth_conf_msg_size', test.msg_size)  # size of confirmation message              
            
                                       
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
            actual = G().used_timeouts['SEC 1']["['ECUAuthenticator', 'SSMA_ENCR_CONF_MSG_ECU_KEY']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
        
    def test_t_str_auth_decr_req_msg(self):
        '''
        coresponding global SSMA_STREAM_REQ_INI_DECR
        
        If a ECU wants to send a message it sends a request message
        This message is encrypted using symmetric encryption. The time
        this decryption takes is tested here
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_STREAM_REQ_INI_DECR
        # Influencing parameters:      
            - Algorithm (and mode) set for the decryption 
            - Keylength used in the decryption
            - library used in the decryption
            - size of the request message
           
        Operation: symmetric decryption
        '''
        return
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
            cipher_size = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'ENCRYPTION')  
            test.expected = TimingDBMap().lookup_interpol(lib=test.lib, mode='DECRYPTION', alg_mode=test.mode, keylen=test.key_len, alg=test.algo, data_size=cipher_size)
            
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
            actual = G().used_timeouts['SEC 1']["['StreamAuthorizer', 'SSMA_STREAM_REQ_INI_DECR']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
        
    def test_t_str_auth_enc_deny_msg(self):
        '''
        coresponding global SSMA_STREAM_ENC_DENY_MSG
        
        If a ECU is not allowed to send a stream but asks 
        for it it will receive a deny message. The time teh Sec Mod 
        needs to encrypt the deny message is tested here
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_STREAM_ENC_DENY_MSG
        # Influencing parameters:      
            - Algorithm (and mode) set for the decryption 
            - Keylength used in the decryption
            - library used in the decryption
            - size of the request message
           
        Operation: symmetric decryption
        '''
        return

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
                                  
            ecu_spec.set_ecu_setting('p_grant_msg_content_size', test.msg_size)  # size of the deny message             
                
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
            actual = G().used_timeouts['SEC 1']["['StreamAuthorizer', 'SSMA_STREAM_ENC_DENY_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_t_str_auth_enc_grant_msg(self):
        '''
        coresponding global SSMA_STREAM_ENC_GRANT_MSG
        
        If a ECU is allowed to send a stream ans asks 
        for it it will receive a grant message. The time to
        decrypt the received message is tested here
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_STREAM_ENC_GRANT_MSG
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
                                  
            ecu_spec.set_ecu_setting('p_grant_msg_content_size', test.msg_size)  # size of the deny message             
                
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
            actual = G().used_timeouts['SEC 1']["['StreamAuthorizer', 'SSMA_STREAM_ENC_GRANT_MSG']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("time %s seconds ... ok" % actual)
        assert_true(True)
    
    def test_t_str_auth_keygen_grant_msg(self):
        '''
        TODOOOOOOOOOOOOO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        coresponding global SSMA_SESS_KEYGEN_GRANT_MSG
        
        The session key that encrypts the messages is generated with
        this algorithm. The time this generation takes is tested here
        
        fixed values for this timeout were already tested
        if it has the expected value: so certain digit
        
        # Corresponding project value: SSMA_SESS_KEYGEN_GRANT_MSG
        # Influencing parameters:      
            - Algorithm (and mode) set for the decryption 
            - Keylength used in the decryption
            - library used in the decryption
           
        Operation: symmetric keygeneration
        '''
    
    '''===========================================================================
             Private methods
    ==========================================================================='''
    def _init_part(self):
        self._av_proj_settings = [ i for n, i in enumerate(list(SecLwAuthSecurityModule().settings.keys())) if i[0] != 't' ]
        self._av_timing_settings = [ i for n, i in enumerate(list(SecLwAuthSecurityModule().settings.keys())) if i[0] == 't' ]
        self._av_settings = list(SecLwAuthSecurityModule().settings.keys())


        # Setup the environment with default settings
        api_log_path = r"C:\Users\artur.mrowca\Desktop\api.log"
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
        
    def _ecu_spec_timing_application(self, main_lib='CyaSSL'):        
        t_set2 = TimingFunctionSet() 
        ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=main_lib)
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

    def _sec_mod_spec_creation(self):
        # Security Module
        ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)  
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)  
        self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]

    def _sec_mod_timing_set(self, main_lib_tag='CyaSSL'):
        t_set = TimingFunctionSet()
        ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=main_lib_tag)
        t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
        api.apply_timing_functions_set(self.env, 'SEC 1', t_set)

    def _sec_mod_creation_part(self):
        
        self._sec_mod_spec_creation()
        
        self._sec_mod_timing_set()
    
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








