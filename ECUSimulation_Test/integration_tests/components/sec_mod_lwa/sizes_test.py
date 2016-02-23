'''
Tests depending on all selected variables
if the sizes are set correctly 
and if the timeout values in the program
use the expected input sizes 
(input algorithms etc. already tested in timings_test.py)
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

import unittest2 as unittest
from tools.general import General as G
from config.timing_db_admin import TimingDBMap
from components.security.encryption.encryption_tools import EncryptionSize
from numpy.core.defchararray import isnumeric
from enums.sec_cfg_enum import CAEnum, EnumTrafor
from components.security.certification.certificates import EcuCertificate
from integration_tests.components.secure_ecu.settings_test import TestConfigComponent


class SecLwAuthSecurityModuleSizesIntegrationTest(unittest.TestCase):
    '''
        Classes under test: (Regular)SecureECU, StdSecureECUTimingFunctions, SecureCommModule
    
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
             Sizes - Tests
             
             bekommt jede Timeoutfunktion die richtige Groesse als Input?
             werden alle Groessen, die ueberhaupt vorkommen (sending size, clear size,...) richtig gesetzt?
    ==========================================================================='''
        
    def test_fixed_sizes_used(self):
        ''' 
            this test checks if all size settings are connected properly
            Expected behaviour:
            if the size parameter was set to a random fixed variable a random
            fixed variable will be used for the size in the corresponding method
            ''' 
        return
        # Prepare        
        self._init_part()
        test_dict = {}

        ecu_spec1 = RegularECUSpec(["Test_ECU_1"], 200, 200)
        ecu_spec1.add_sending_actions(150, 1.5, can_registration.CAN_TEST_MSG, "TEST STRING A", 50)  # granted
        ecu_spec2 = RegularECUSpec(["Test_ECU_2"], 200, 200) 
        ecu_spec2.add_sending_actions(110, 1.5, can_registration.CAN_TEST_MSG, "TEST STRING B", 50)  # Denied    
        ecu_spec3 = SimpleECUSpec(["Test_ECU_3"], 200, 200)
        self.ecu_group_1 = api.set_ecus(self.env, 1, 'RegularSecureECU', ecu_spec1)    
        self.ecu_group_2 = api.set_ecus(self.env, 1, 'RegularSecureECU', ecu_spec2)
        self.ecu_group_3 = api.set_ecus(self.env, 1, 'SecureECU', ecu_spec3) 
        t_set2 = TimingFunctionSet() 
        ecu_func_set = StdSecurECUTimingFunctions(main_library_tag="CyaSSL")
        for ecu in APICore()._ecu_list_from_groups([[self.ecu_group_1 + self.ecu_group_2 + self.ecu_group_3]]):  # UNINTENDED HACK
            t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
            api.apply_timing_functions_set(self.env, ecu.ecu_id, t_set2) 
         
        
        # create settings
        test_settings_sec_mod = []  # set in the sec mod

        test_settings_sec_mod.append(['p_sec_mod_cert_size', "['SEC 1', 'SSMA_SECM_CERT_SIZE']"])  # Advertisement message size: p_sec_mod_cert_size
        test_settings_sec_mod.append(['p_reg_msg_inner_cipher_size', "['SEC 1', 'SSMA_REG_MSG_CIPHER_SIZE_INNER']"])  
        test_settings_sec_mod.append(['p_reg_msg_inner_content_size', "['SEC 1', 'SSMA_REG_MSG_CT_SIZE_INNER']"])
        test_settings_sec_mod.append(['p_reg_msg_outter_hash_size', "['SEC 1', 'SCCM_ECU_REG_MSG_HASH_LEN']"])
        test_settings_sec_mod.append(['p_reg_msg_outter_cipher_size', "['SEC 1', 'SSMA_REG_MSG_CIPHER_SIZE_OUTER']"])
        test_settings_sec_mod.append(['p_ecu_auth_cert_hash_unsigned_size', "['SEC 1', 'ECU_CERT_SIZE_HASH_TO_SIGN']"])
        test_settings_sec_mod.append(['p_ecu_auth_cert_hash_signed_size', "['SEC 1', 'ECU_CERT_SIZE_HASH']"]) 
        test_settings_sec_mod.append(['p_ecu_auth_conf_msg_size', "['SEC 1', 'SCCM_ECU_CONF_MSG_SIZE']"])        
        test_settings_sec_mod.append(['p_sec_mod_conf_msg_sending_size', "['SEC 1', 'SSMA_SECM_CONF_MSG_SIZE']"])        
        test_settings_sec_mod.append(['p_req_msg_cipher_size', "['SEC 1', 'SSMA_SIZE_REQ_MSG_CIPHER']"])        
        test_settings_sec_mod.append(['p_req_msg_content_size', "['SEC 1', 'SSMA_SIZE_REQ_MSG_CONTENT']"])
        test_settings_sec_mod.append(['p_str_auth_deny_msg_sending_size', "['SEC 1', 'SSMA_SECM_DENY_MSG_SIZE']"])  
        test_settings_sec_mod.append(['p_str_auth_grant_msg_sending_size', "['SEC 1', 'SSMA_SECM_GRANT_MSG_SIZE']"])
        test_settings_sec_mod.append(['p_grant_msg_content_size', "['SEC 1', 'SSMA_GRANT_MSG_CT_SIZE']"])

        # Security Module: Set settings
        ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)  
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)  
         
        for test_set in test_settings_sec_mod:
            val = round(random.random() * 200)
            ecu_spec.set_ecu_setting(test_set[0], val) 
            test_dict[test_set[0]] = val
                  
        self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)[0]        
        t_set = TimingFunctionSet()
        ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag='CyaSSL')
        t_set.set_mapping_from_function_set('SEC 1', ecu_func_set)
        api.apply_timing_functions_set(self.env, 'SEC 1', t_set)
         
        # Further Options
        self._bus_creation_part()
        self._ecu_to_sec_mod_part()        
        self._set_streams_part()        
        self._run_part()
         
        # Check results        
        print("Checking results...")
        for test_set in test_settings_sec_mod:
            if G().noted_sizes[test_set[1]] != test_dict[test_set[0]]:
                print("Error for %s to [%s, %s]" % (test_set[1], test_set[2], test_set[0]))
                assert_true(False)
        assert_true(True)
        
    def test_SSMA_REG_MSG_CIPHER_SIZE_INNER(self):
        '''
        tests if this size is calculated and used
        correctly
        
        this size is used to decrypt the registration message.
        It is calculated from the clear part of the reg. message
        
        it should be calculated from:
            - the size of the inner registration message                          SSMA_REG_MSG_CT_SIZE_INNER
            - the encryption method of the inner registration message             SSMA_SECM_PUB_ENC_ALG
            - the keylength of the inner registration message                     SSMA_SECM_PUB_ENC_KEY_LEN
            
        operation - automatic calculation of the size: encryption
        '''  
        
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
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s: %s - %s , len: %s, hash: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.hash_mech, test.lib)); i += 1
            
            # preprocess
            self._init_part()
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            sec_mod_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            # Set Settings
            # ECU and SecMod:
            self.ecu_spec_1.set_ecu_setting('p_reg_msg_sending_size', 50)  # DUMMY
            self.ecu_spec_3.set_ecu_setting('p_reg_msg_sending_size', 50)  # DUMMY
            self.ecu_spec_2.set_ecu_setting('p_reg_msg_sending_size', 50)  # DUMMY
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)             
            sec_mod_spec.set_ecu_setting('p_reg_msg_inner_content_size', test.msg_size)  # reg cntnt size before hash and sign
            sec_mod_spec.set_ecu_setting('p_reg_msg_inner_enc_method', EnumTrafor().to_enum(test.algo))
            sec_mod_spec.set_ecu_setting('p_reg_msg_inner_enc_keylen', EnumTrafor().to_enum(test.key_len))

            # Run Test    
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)                                       
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', sec_mod_spec)[0]  
            self._sec_mod_timing_set(test.lib)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected (=signed size)
            # size of reg msg -> public encrypted size
            expected = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'ENCRYPTION')
            
            # actual
            actual = G().noted_sizes["['SEC 1', 'SSMA_REG_MSG_CIPHER_SIZE_INNER']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("size %s Bytes ... ok" % actual)
        assert_true(True)  
           
    def test_SCCM_ECU_REG_MSG_HASH_LEN(self):
        '''
        tests if this size is calculated and used
        correctly
        
        the inner registration message is hashed and has this
        length after the hashing operation
        
        set the size of the inner registration content and check if
        the hashed size was calculated from it correctly
        
        it should be calculated from:
            - the size of the inner registration message SSMA_REG_MSG_CT_SIZE_INNER
            - the hashing method     SCCM_ECU_REG_MSG_HASH
            
        operation - automatic calculation of the size after: hash
        '''  
        return
        
        test_scenarios = []
        
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='MD5', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA1', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA256', lib='Crypto_Lib_SW'))      
                
        # CyaSSL
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='MD5', algo="RSA", key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA1', algo="RSA", key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA256', algo="RSA", key_len=512, lib='CyaSSL'))
        
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s:, hash: %s, lib: %s" % (i, len(test_scenarios), test.hash_mech, test.lib)); i += 1
            
            # preprocess
            self._init_part()
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            sec_mod_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            # Set Settings
            # ECU and SecMod:
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)             
            sec_mod_spec.set_ecu_setting('p_reg_msg_inner_content_size', test.msg_size)  # reg cntnt size before hash and sign
            sec_mod_spec.set_ecu_setting('p_reg_msg_hash_alg', EnumTrafor().to_enum(test.hash_mech))

            # Run Test    
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)                                       
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', sec_mod_spec)[0]  
            self._sec_mod_timing_set(test.lib)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected (=signed size)
            # size of certificate -> hashed_size -> signed_size
            expected = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.hash_mech), None, 'HASH')
            
            # actual
            actual = G().noted_sizes["['SEC 1', 'SCCM_ECU_REG_MSG_HASH_LEN']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("size %s Bytes ... ok" % actual)
        assert_true(True)    
        
    def test_SSMA_REG_MSG_CIPHER_SIZE_OUTER(self):
        '''
        tests if this size is calculated and used
        correctly
        
        the outer registration message cipher is created from the hashed version of
        the inner registration message. 

        
        set the size of the inner registration content and check if
        the outer registration message cipher size was calculated from it correctly
        
        it should be calculated from:
            - the size of the inner registration message                         SSMA_REG_MSG_CT_SIZE_INNER
            - the hashing method of the inner registration message               SCCM_ECU_REG_MSG_HASH
            - the encryption method of the hashed inner registration message     SCCM_ECU_PUB_ENC_ALG
            - the keylength of the hashed inner registration message         SCCM_ECU_PUB_ENC_KEY_LEN
            
        operation - automatic calculation of the size after: hash and sign
        '''  
        return
        test_scenarios = []
        
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
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s: %s - %s , len: %s, hash: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.hash_mech, test.lib)); i += 1
            
            # preprocess
            self._init_part()
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            sec_mod_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            # Set Settings
            # ECU and SecMod:
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)        
            self.ecu_spec_1.set_ecu_setting('p_reg_msg_sending_size', 50)  # DUMMY
            self.ecu_spec_3.set_ecu_setting('p_reg_msg_sending_size', 50)  # DUMMY
            self.ecu_spec_2.set_ecu_setting('p_reg_msg_sending_size', 50)  # DUMMY
                 
            sec_mod_spec.set_ecu_setting('p_reg_msg_inner_content_size', test.msg_size)  # reg cntnt size before hash and sign
            sec_mod_spec.set_ecu_setting('p_reg_msg_hash_alg', EnumTrafor().to_enum(test.hash_mech))
            sec_mod_spec.set_ecu_setting('p_reg_msg_outter_enc_alg', EnumTrafor().to_enum(test.algo))
            sec_mod_spec.set_ecu_setting('p_reg_msg_outter_enc_keylen', EnumTrafor().to_enum(test.key_len))


            # Run Test    
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)                                       
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', sec_mod_spec)[0]  
            self._sec_mod_timing_set(test.lib)
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected (=signed size)
            # size of reg msg -> hashed_size -> signed_size
            hashed_size = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.hash_mech), None, 'HASH')
            expected = EncryptionSize().output_size(hashed_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'SIGN')
            
            # actual
            actual = G().noted_sizes["['SEC 1', 'SSMA_REG_MSG_CIPHER_SIZE_OUTER']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("size %s Bytes ... ok" % actual)
        assert_true(True)  
               
    def test_ECU_CERT_SIZE_HASH(self):
        '''
        tests if this size is calculated and used
        correctly
        
        the signed size of the ecu certificate 
        
        set the size of the inner registration content and check if
        the hashed size was calculated from it correctly

            
        operation - automatic calculation of the size after: sign
        ''' 
        return
        test_scenarios = []
        
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='MD5', algo="RSA", key_len=512, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='MD5', algo="RSA", key_len=1024, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='MD5', algo="RSA", key_len=2048, lib='Crypto_Lib_SW'))
          
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA1', algo="RSA", key_len=512, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA1', algo="RSA", key_len=1024, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA1', algo="RSA", key_len=2048, lib='Crypto_Lib_SW'))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA256', algo="RSA", key_len=512, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA256', algo="RSA", key_len=1024, lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA256', algo="RSA", key_len=2048, lib='Crypto_Lib_SW'))      
                
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=192, hash_mech='MD5', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=256, hash_mech='MD5', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=384, hash_mech='MD5', lib='Crypto_Lib_SW'))
        
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=192, hash_mech='SHA1', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=256, hash_mech='SHA1', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=384, hash_mech='SHA1', lib='Crypto_Lib_SW'))

        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=192, hash_mech='SHA256', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=256, hash_mech='SHA256', lib='Crypto_Lib_SW'))
        test_scenarios.append(TestConfigComponent(msg_size=123, ca_len=5, algo="ECC", key_len=384, hash_mech='SHA256', lib='Crypto_Lib_SW'))
        
        # CyaSSL
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='MD5', algo="RSA", key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='MD5', algo="RSA", key_len=1024, lib='CyaSSL'))
          
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA1', algo="RSA", key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA1', algo="RSA", key_len=1024, lib='CyaSSL'))
        
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA256', algo="RSA", key_len=512, lib='CyaSSL'))
        test_scenarios.append(TestConfigComponent(msg_size=167, hash_mech='SHA256', algo="RSA", key_len=1024, lib='CyaSSL'))
        
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
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s: %s - %s , len: %s, hash: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.hash_mech, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            sec_mod_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            # Set Settings
            # ECU and SecMod:
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)             
            sec_mod_spec.set_ecu_setting('p_ecu_auth_cert_hash_unsigned_size', test.msg_size)  # certificate size before  sign
            sec_mod_spec.set_ecu_setting('p_ecu_auth_cert_enc_mech', EnumTrafor().to_enum(test.algo))
            sec_mod_spec.set_ecu_setting('p_ecu_auth_cert_enc_keylen', EnumTrafor().to_enum(test.key_len))

            # Run Test    
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)                                       
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', sec_mod_spec)[0]  
            self._sec_mod_timing_set(test.lib)            
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected (=signed size)
            # size of certificate -> hashed_size -> signed_size
            hashed_size = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.hash_mech), None, 'HASH')
            expected = EncryptionSize().output_size(hashed_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'SIGN')

            # actual
            actual = G().noted_sizes["['SEC 1', 'ECU_CERT_SIZE_HASH']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("size %s Bytes ... ok" % actual)
        assert_true(True)
        
    def test_SSMA_SECM_CONF_MSG_SIZE(self):
        '''
        tests if this size is calculated and used
        correctly
        
        the size of the symmetric encrypted confirmation message
                
        set the size of the unencrypted confirmation message and check if the 
        encrypted size suites
            
        operation -symmetric encryption
        '''  
        return
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []      
        val = round(random.random() * 200)  
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        i = 1
        print("\n")
        for test in test_scenarios:
            val = round(random.random() * 200)  
            test.msg_size = val
            
            print("Scenario %s/%s: %s - %s , len: %s, hash: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.hash_mech, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            sec_mod_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            # Set Settings
            # ECU and SecMod:
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)             
            sec_mod_spec.set_ecu_setting('p_ecu_auth_conf_msg_size', test.msg_size)  # Set the conf. size 
            sec_mod_spec.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))  # Set the conf. size 
            sec_mod_spec.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))  # Set the conf. size 
            
            # Run Test    
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)                                       
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', sec_mod_spec)[0]  
            self._sec_mod_timing_set(test.lib)            
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected (=signed size)
            # size of certificate -> signed_size
            expected = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'ENCRYPTION')

            # actual
            actual = G().noted_sizes["['SEC 1', 'SSMA_SECM_CONF_MSG_SIZE']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("clear: %s -> then size %s Bytes ... ok" % (val, actual))
        assert_true(True)
        
    def test_SSMA_SIZE_REQ_MSG_CIPHER(self):
        '''
        tests if this size is calculated and used
        correctly
        
        the size of the request message after encryption is
        tested
                
        set the size of the unencrypted confirmation message and check if the 
        encrypted size suites
            
        operation -symmetric encryption
        '''  
        return
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []      
        val = round(random.random() * 200)  
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        i = 1
        print("\n")
        for test in test_scenarios:
            val = round(random.random() * 200)  
            test.msg_size = val
            
            print("Scenario %s/%s: %s - %s , len: %s, hash: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.hash_mech, test.lib)); i += 1
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            sec_mod_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            # Set Settings
            # ECU and SecMod:
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)             
            sec_mod_spec.set_ecu_setting('p_req_msg_content_size', test.msg_size)  # Set the req. size 
            sec_mod_spec.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))  # Set the req. size 
            sec_mod_spec.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))  # Set the req. size 
            
            # Run Test    
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)                                       
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', sec_mod_spec)[0]  
            self._sec_mod_timing_set(test.lib)            
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()
            self._run_part()
            
            # expected (=signed size)
            # size of certificate -> signed_size
            expected = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'ENCRYPTION')

            # actual
            actual = G().noted_sizes["['SEC 1', 'SSMA_SIZE_REQ_MSG_CIPHER']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("clear: %s -> then size %s Bytes ... ok" % (val, actual))
        assert_true(True)
        
    def test_SSMA_SECM_DENY_MSG_SIZE(self):
        '''
        tests if this size is calculated and used
        correctly
        
        the ECU receives a deny message. The size of this 
        deny message is the encrypted size of SSMA_GRANT_MSG_CT_SIZE
        

        it should be calculated from:
            - the size of the deny message:      SSMA_GRANT_MSG_CT_SIZE
            - the encryption method              SCCM_ECU_SYM_KEY_ENC_ALG
            - the keylength                      SCCM_ECU_SYM_KEY_ENC_KEY_LEN
            
        operation - automatic calculation of the size after: symmetric encryption
        '''  
        return
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []      
        val = round(random.random() * 200)  
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s: %s - %s , len: %s, hash: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.hash_mech, test.lib)); i += 1
            test.msg_size = round(random.random() * 200)
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            sec_mod_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            # Set Settings
            # ECU and SecMod:
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)             
            sec_mod_spec.set_ecu_setting('p_grant_msg_content_size', test.msg_size)  # Set the req. msg. size 
            sec_mod_spec.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))  # Set the conf. size 
            sec_mod_spec.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))  # Set the conf. size 
            
            # Run Test    
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)                                       
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', sec_mod_spec)[0]  
            self._sec_mod_timing_set(test.lib)            
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            stream_1 = MessageStream('Test_ECU_12', ['Test_ECU_2', 'Test_ECU_3'], can_registration.CAN_TEST_MSG, float('inf'), 0, float('inf'))
            api.add_allowed_stream(self.env, 'SEC 1', stream_1)
            api.autoset_gateway_filters(self.env, 'SEC 1')        
            self._run_part()
            
            # expected (=signed size)
            # size of certificate -> signed_size
            expected = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'ENCRYPTION')

            # actual
            actual = G().noted_sizes["['SEC 1', 'SSMA_SECM_DENY_MSG_SIZE']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("clear: %s -> then size %s Bytes ... ok" % (val, actual))
        assert_true(True)
        
    def test_SSMA_SECM_GRANT_MSG_SIZE(self):
        '''
        tests if this size is calculated and used
        correctly
        
        the ECU receives a deny message. The size of this 
        deny message is the encrypted size of SSMA_GRANT_MSG_CT_SIZE
        

        it should be calculated from:
            - the size of the grant message:      SSMA_GRANT_MSG_CT_SIZE
            - the encryption method              SCCM_ECU_SYM_KEY_ENC_ALG
            - the keylength                      SCCM_ECU_SYM_KEY_ENC_KEY_LEN
            
        operation - automatic calculation of the size after: symmetric encryption
        '''  
        return
        # Preprocess: Save all allowed combinations of Configs            
        test_scenarios = []      
        val = 0
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=128, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=192, lib='CyaSSL', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CBC', key_len=256, lib='CyaSSL', validity=1000))
        
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=128, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=192, lib='Crypto_Lib_HW', validity=1000))
        test_scenarios.append(TestConfigComponent(msg_size=val, algo="AES", mode='CTR', key_len=256, lib='Crypto_Lib_HW', validity=1000))
        
        i = 1
        print("\n")
        for test in test_scenarios:
            print("Scenario %s/%s: %s - %s , len: %s, hash: %s, lib: %s" % (i, len(test_scenarios), test.algo, test.mode, test.key_len, test.hash_mech, test.lib)); i += 1
            
            test.msg_size = round(random.random() * 200) 
            
            # preprocess
            self._init_part()        
            self.env = api.create_environment(200)
            self._ecu_spec_creation() 
            sec_mod_spec = SimpleECUSpec(['SEC 1'], 200, 200)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_process', 10)
            sec_mod_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 10000)
            
            # Set Settings
            # ECU and SecMod:
            self.ecu_spec_1.set_ecu_setting('t_adv_msg_secmodcert_enc', 0.1)             
            sec_mod_spec.set_ecu_setting('p_grant_msg_content_size', test.msg_size)  # Set the req. msg. size 
            sec_mod_spec.set_ecu_setting('p_ecu_sym_key_alg', EnumTrafor().to_enum(test.algo))  # Set the conf. size 
            sec_mod_spec.set_ecu_setting('p_ecu_sym_key_keylen', EnumTrafor().to_enum(test.key_len))  # Set the conf. size 
            
            # Run Test    
            self._ecu_spec_application()
            self._ecu_spec_timing_application(test.lib)                                       
            self.sec_mod = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', sec_mod_spec)[0]  
            self._sec_mod_timing_set(test.lib)            
            self._bus_creation_part()
            self._ecu_to_sec_mod_part()        
            self._set_streams_part()   
            self._run_part()
            
            # expected (=signed size)
            # size of certificate -> signed_size
            expected = EncryptionSize().output_size(test.msg_size, EnumTrafor().to_enum(test.algo), EnumTrafor().to_enum(test.key_len), 'ENCRYPTION')

            # actual
            actual = G().noted_sizes["['SEC 1', 'SSMA_SECM_GRANT_MSG_SIZE']"]

            if expected != actual:
                assert actual == expected
                
            if not isinstance(actual, (int, float, complex, numpy.ndarray)):
                assert_true(False)
            
            print("clear: %s -> then size %s Bytes ... ok" % (val, actual))
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








