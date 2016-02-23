import unittest2 as unittest
from api.core.api_core import APICore, TimingFunctionSet
from mock import MagicMock, Mock
from api.core.component_specs import AutomotiveEnvironmentSpec, RegularECUSpec, \
    SimpleECUSpec, SimpleBusSpec
from components.security.communication.stream import MessageStream
from config import can_registration
from components.security.certification.certification_authority import CAHierarchy
from components.security.certification.cert_manager import CertificateManager

from nose.tools import assert_true
from api.core.component_factories import ECUFactory
from enums.sec_cfg_enum import CAEnum
from components.security.encryption import encryption_tools
import os
from components.base.bus.impl_bus_can import StdCANBus
from io_processing.surveillance import Monitor

class APICoreTest(unittest.TestCase):
    
    '''===========================================================================
             Setup/Teardown
    ==========================================================================='''
    def setUp(self):        
#         print("Reset APICore")        
        self.api_core = APICore()        
        self.env = AutomotiveEnvironmentSpec(50)        
    
    def dummy(self):
        return 20
    
    def test_apply_timing_functions_set(self):
        
        # Prepare input
        time_func_set = TimingFunctionSet()
        time_func_set.set_mapping('my_component_id', 'time_id', self.dummy)
        time_func_set.set_mapping('my_component_id2', 'time_id2', self.dummy)
        self.env.timing_map = {}
       
        # expected
        expected = {'my_component_id':{'time_id':self.dummy}, 'my_component_id2':{'time_id2':self.dummy}}
        
        # actual 
        self.api_core.apply_timing_functions_set(self.env, 'my_component_id', time_func_set)
        self.api_core.apply_timing_functions_set(self.env, 'my_component_id2', time_func_set)
        
        # compare        
        assert self.env.timing_map == expected
    
    def test_apply_timing_function_ind(self):
        
        # Prepare input
        time_func_set = TimingFunctionSet()
        time_func_set.set_mapping('my_component_id', 'time_id', self.dummy)
        time_func_set.set_mapping('my_component_id2', 'time_id2', self.dummy)
        self.env.timing_map = {}
       
        # expected
        expected = {'my_component_id':{'time_id':self.dummy}, 'my_component_id2':{'time_id2':self.dummy}}
        
        # actual 
        self.api_core.apply_timing_function_ind(self.env, 'my_component_id', 'time_id', time_func_set)
        self.api_core.apply_timing_function_ind(self.env, 'my_component_id2', 'time_id2', time_func_set)
        
        # compare        
        assert self.env.timing_map == expected

    def test_add_allowed_stream_correct_streams(self):
            
        # Prepare input 
        ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
        sec_mod_group = self.api_core.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)
        
        # expected
        test_stream_1 = MessageStream(self.env.get_env(), 'Test_IN', ['TEST_OUT_1', 'TEST_OUT_2', 'TEST_OUT_3'], 1, float('inf'), 0, float('inf'))
        test_stream_2 = MessageStream(self.env.get_env(), 'Test_IN', ['TEST_OUT_1', 'TEST_OUT_2', 'TEST_OUT_3'], 1, float('inf'), 0, float('inf'))
        test_stream_3 = MessageStream(self.env.get_env(), 'Test_IN', ['TEST_OUT_1', 'TEST_OUT_2', 'TEST_OUT_3'], 1, float('inf'), 0, float('inf'))
        expected = [test_stream_1, test_stream_2, test_stream_3]
        
        # actual
        self.api_core.add_allowed_stream(self.env, 'SEC 1', test_stream_1)
        self.api_core.add_allowed_stream(self.env, 'SEC 1', test_stream_2)
        self.api_core.add_allowed_stream(self.env, 'SEC 1', test_stream_3)
        actual = sec_mod_group[0].ecuSW.app_lay.stream_auth.allowed_streams
        
        # Compare
        assert actual == expected
        
    def test_add_allowed_stream_correct_hw_filter(self):
            
        # Prepare input 
        ecu_spec = SimpleECUSpec(['SEC 1'], 200, 200)
        self.api_core.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', ecu_spec)
        
        ecu_spec = RegularECUSpec(["TEST_ECU"], 200, 200)
        ecu_group = self.api_core.set_ecus(self.env, 1, 'RegularSecureECU', ecu_spec)
        
        # expected
        test_stream_1 = MessageStream(self.env.get_env(), 'Test_IN', ['TEST_ECU', 'TEST_OUT_2', 'TEST_OUT_3'], 10, float('inf'), 0, float('inf'))
        test_stream_2 = MessageStream(self.env.get_env(), 'Test_IN', ['TEST_OUT_1', 'TEST_OUT_2', 'TEST_ECU'], 20, float('inf'), 0, float('inf'))
        test_stream_3 = MessageStream(self.env.get_env(), 'Test_IN', ['TEST_OUT_1', 'TEST_OUT_2', 'TEST_OUT_3'], 30, float('inf'), 0, float('inf'))
        
        expected_1 = [10, 20] + can_registration.AUTH_MESSAGES
        expected_2 = True
        
        # actual
        self.api_core.add_allowed_stream(self.env, 'SEC 1', test_stream_1)
        self.api_core.add_allowed_stream(self.env, 'SEC 1', test_stream_2)
        self.api_core.add_allowed_stream(self.env, 'SEC 1', test_stream_3)
                
        actual_1 = ecu_group[0].ecuHW.transceiver.allowed_items
        actual_2 = ecu_group[0].ecuHW.transceiver.filter_active
        
        # Compare
        assert (actual_1 == expected_1 and actual_2 == expected_2)
    
    def test_apply_certification_manager_set(self):
        
        # expected
        expected_1 = self.api_core.cert_manager(None)
        expected_2 = True
        
        # actual 
        self.api_core.apply_certification(self.env, expected_1)
        actual_1 = self.env.cert_manager
        actual_2 = self.env.apply_certification

        # Compare
        assert (actual_1 == expected_1 and actual_2 == expected_2)

    def test_build_sim_param(self):
        # TODO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        pass
    
    def test_cert_manager_set_correct(self):
        
        # Prepare
        cert_in = CAHierarchy()

        # expected
        expected = CertificateManager(cert_in).__dict__
        
        # actual
        actual = self.api_core.cert_manager(cert_in).__dict__
        
        # Compare
        assert actual == expected
        
    def test_connect_bus_add_lst(self):
        
        # Prepare 
        bus_id_1 = 'bus_1'
        add_1 = ['A', 'B', 'C']
        bus_id_2 = 'bus_2'
        add_2 = ['D', 'E', 'F']
        
        # Expected
        expected = [['bus_1', 'A'], ['bus_1', 'B'], ['bus_1', 'C'], \
                    ['bus_2', 'D'], ['bus_2', 'E'], ['bus_2', 'F']]
        
        # actual
        self.api_core.connect_bus(self.env, bus_id_1, add_1)
        self.api_core.connect_bus(self.env, bus_id_2, add_2)
        actual = self.env.bus_connections

        # Compare
        assert actual == expected

    def test_connect_bus_obj_add_object(self):
        
        # Prepare 
        bus_id_1 = 'bus_1'

        ecu_spec = RegularECUSpec(["A", "B", "C"], 200, 200)
        ecu_group = self.api_core.set_ecus(self.env, 3, 'RegularSecureECU', ecu_spec)
        
        # Expected
        expected = [['bus_1', 'A'], ['bus_1', 'B'], ['bus_1', 'C']]
        
        # actual
        self.api_core.connect_bus_obj(self.env, bus_id_1, ecu_group)
        actual = self.env.bus_connections

        # Compare
        assert actual == expected

    def test_connect_monitor_ecus_connect_monitor(self):
        
        # Prepare inputs            
        ecu_group = self.api_core.set_ecus(self.env, 3, 'RegularSecureECU', RegularECUSpec(["A", "B", "C"], 200, 200))
        
        # Expected
        monitor = Monitor()   
        expected = monitor
        
        # actual: ECU has monitor and monitor has ecu
        self.api_core.connect_monitor(self.env, monitor, 20)
        actual_1 = ecu_group[0].monitor
        
        cond_1 = (actual_1 == expected)
        cond_2 = (ecu_group[0] in monitor.monitored)
                
        assert_true(cond_1 and cond_2)
        
    def test_connect_monitor_monitor_has_correct_time(self):
         
        # Prepare inputs            
        self.api_core.set_ecus(self.env, 3, 'RegularSecureECU', RegularECUSpec(["A", "B", "C"], 200, 200))
 
        # Expected
        monitor = Monitor()   
        expected = 20
          
        # actual: ECU has monitor and monitor ecu
        self.api_core.connect_monitor(self.env, monitor, 20)         
        actual = monitor.t_period
        
        assert actual == expected
 
    def test_connect_monitor_bus_connect_monitor(self):
        # Todo: Bus not monitored so far
        pass
    
    def test_create_environment_life_time_set(self):
        
        # Prepare inputs
        test_env = self.api_core.create_environment(200)

        # Expected
        expected = 200
    
        # actual
        actual = test_env.app_lifetime
        
        # Compare
        assert actual == expected
        
    def test_generate_valid_ecu_cert_cfg_ecu_certificate_is_valid_for_sec_module(self):
        ''' generate certificates of the Security module for all ECUs that are mentioned
            in the list relevant_ecus. Tests if the certificate of all ECUs are set in 
            the security module and if they can be verified by the security module.
            
            Can the security module verify the ECU?'''

        # Prepare Inputs
        sec_mod = self.api_core.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', SimpleECUSpec(['SEC 1'], 200, 200))[0]        
        relevant_ecus = ['RegularSecureECU', 'SecureECU']
        ecu_group = []
        for obj_name in ECUFactory().createable_objects():
            if obj_name == 'RegularSecureECU': spec = RegularECUSpec(["A", "B", "C"], 200, 200)
            else: spec = SimpleECUSpec(["A1", "B1", "C1"], 200, 200)            
            if obj_name in relevant_ecus:
                ecu_group += self.api_core.set_ecus(self.env, 3, obj_name, spec)
 
        # actual
        cm = CertificateManager()
        for ecu in ecu_group:
            self.api_core.generate_valid_ecu_cert_cfg(cm, ecu.ecu_id, CAEnum.CA_L311, sec_mod.ecu_id, 0, float("inf"))
        self.api_core.apply_certification(self.env, cm)
        self.api_core._apply_certification(self.env)
        sec_root_cert_lst = sec_mod.ecuSW.app_lay.ecu_auth.lst_root_certificates
        cond = True
        for ecu in ecu_group:
            ecu_cert = ecu.ecuSW.comm_mod.authenticator.ecu_certificate  # Certificate of the ECU
            cond = encryption_tools.certificate_trustworthy(ecu_cert, sec_root_cert_lst, 15)            
            if not cond:
                break
        
        # Compare
        assert_true(cond)
        
    def test_generate_valid_ecu_cert_cfg_sec_mod_certificate_is_valid_for_ecu(self):
        ''' generate certificates of all ECUs that are mentioned
            in the list relevant_ecus. Tests if all ECUs have the root certificates
            for the Security module and thus are able to authenticate the Security Module.   
                     
            Can the ECU verify the Security Module?
            '''

        # Prepare Inputs
        sec_mod = self.api_core.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', SimpleECUSpec(['SEC 1'], 200, 200))[0]        
        relevant_ecus = ['RegularSecureECU', 'SecureECU']
        ecu_group = []
        for obj_name in ECUFactory().createable_objects():
            if obj_name == 'RegularSecureECU': spec = RegularECUSpec(["A", "B", "C"], 200, 200)
            else: spec = SimpleECUSpec(["A1", "B1", "C1"], 200, 200)            
            if obj_name in relevant_ecus:
                ecu_group += self.api_core.set_ecus(self.env, 3, obj_name, spec)
 
        # actual
        cm = CertificateManager()
        self.api_core.generate_valid_sec_mod_cert_cfg(cm, CAEnum.CA_L21, 'SEC 1', ["A", "B", "C", "A1", "B1", "C1"], 0, float('inf'))        
        self.api_core.apply_certification(self.env, cm)
        self.api_core._apply_certification(self.env)
        
        sec_cert = sec_mod.ecuSW.app_lay.sec_mod_certificat
        cond = True
        for ecu in ecu_group:
            ecu_root_certs = ecu.ecuSW.comm_mod.authenticator.lst_root_cert  # Root Certificates of ECU
            cond = encryption_tools.certificate_trustworthy(sec_cert, ecu_root_certs, 15)            
            if not cond:
                break
        
        # Compare
        assert_true(cond)
    
    def test_register_bus_classes_bus_is_available(self):
        
        # Prepare Inputs
        test_path = os.path.join(os.path.dirname(__file__), r"../../../test_files/test_folder")
        
        # expected
        expected = 'TestBus'
        
        # actual
        self.api_core.register_bus_classes(test_path)
        actual = self.api_core.set_busses(self.env, 1, 'TestBus', SimpleBusSpec(['CAN_0']))[0].__class__.__name__
        
        # Compare
        assert expected == actual
    
    def test_register_ecu_classes_ecu_is_available(self):
        
        # Prepare Inputs
        test_path = os.path.join(os.path.dirname(__file__), r"../../../test_files/test_folder")
        
        # expected
        expected_1 = 'TestECU1'
        expected_2 = 'TestECU2'
        
        # actual
        self.api_core.register_ecu_classes(test_path)
        actual_1 = self.api_core.set_ecus(self.env, 1, 'TestECU1', SimpleECUSpec(['Test'], 200, 200))[0].__class__.__name__
        actual_2 = self.api_core.set_ecus(self.env, 1, 'TestECU2', SimpleECUSpec(['Test'], 200, 200))[0].__class__.__name__
        
        # Compare
        assert_true(expected_1 == actual_1 and expected_2 == actual_2)
        
    def test_register_ecu_groups_to_secmod_environment_set(self):
        
        # Prepare Inputs
        ecu_group_1 = self.api_core.set_ecus(self.env, 3, 'RegularSecureECU', RegularECUSpec(["A", "B", "C"], 200, 200))
        ecu_group_2 = self.api_core.set_ecus(self.env, 3, 'SecureECU', RegularECUSpec(["D", "E", "F"], 200, 200))
        
        # expect
        expected = {}
        expected['SEC 1'] = [ecu_group_1] + [ecu_group_2]
        
        # actual
        self.api_core.register_ecu_groups_to_secmod(self.env, 'SEC 1', [ecu_group_1])
        self.api_core.register_ecu_groups_to_secmod(self.env, 'SEC 1', [ecu_group_2])
        actual = self.env.sec_mod_ecu_register
        
        # Compare
        assert actual == expected
        
    def test_run_simulation(self):
        # TODO: implement
        pass
    
    def test_set_busses_right_number(self):
        
        # expected
        expected = 4
        
        # actual
        actual = len(self.api_core.set_busses(self.env, 4, 'StdCANBus', SimpleBusSpec(['CAN_0'])))
        
        # Compare
        assert actual == expected
        
    def test_set_busses_correct_type_generated(self):
        
        # expected
        expected = 'StdCANBus'
        
        # actual
        actual = self.api_core.set_busses(self.env, 4, 'StdCANBus', SimpleBusSpec(['CAN_0']))[0].__class__.__name__
        
        # Compare
        assert actual == expected
    
    def test_set_ecus_right_number(self):
        
        # expected
        expected = 3
        
        # actual
        actual = len(self.api_core.set_ecus(self.env, 3, 'SecureECU', RegularECUSpec(["D", "E", "F"], 200, 200)))
        
        # Compare
        assert actual == expected
        
    def test_set_ecus_correct_type_generated(self):
        
        # expected
        expected = 'SecureECU'
        
        # actual
        actual = self.api_core.set_ecus(self.env, 3, 'SecureECU', RegularECUSpec(["D", "E", "F"], 200, 200))[0].__class__.__name__
        
        # Compare
        assert actual == expected
    
    
    
    # TODO: Implement further tests    
    
    
        
        
        
        
        
        
        
        
        
        



