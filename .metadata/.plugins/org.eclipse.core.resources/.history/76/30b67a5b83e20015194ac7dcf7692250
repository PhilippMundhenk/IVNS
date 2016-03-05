#!/usr/bin/env python
'''==================================================================================================
    title:              main_lwa_preset.py
    author:             Artur Mrowca
    last modified:      24/07/2015
    usage:              python main_lwa_preset.py  
    python version:     3.0
    description:        this module exemplarily shows the functionality of the ECUSimulation     
                        project for the Lightweight authentication environment as it is defined 
                        in the paper "Lightweight Authentication for Secure Automotive Networks"
                        by Phillipp Mundhenk et al. It also describes how the API of the ECUSimulation
                        should be used. Thereby the LWASpecPresets is used to setup the project
=================================================================================================='''

import logging
import os
from api.core.api_core import TimingFunctionSet
import api.ecu_sim_api as api
from components.security.ecu.types.impl_ecu_secure import StdSecurECUTimingFunctions
from components.security.ecu.types.impl_sec_mod_lwa import StdSecurLwSecModTimingFunctions
from enums.sec_cfg_enum import CAEnum, HashMechEnum, AsymAuthMechEnum, \
    AuKeyLengthEnum, SymAuthMechEnum
from components.security.communication.stream import MessageStream
import gui.direct_view_window
from components.base.gateways.impl_can_gateway import CANGateway  # @UnusedImport
from config import can_registration
from api.core.component_specs import RegularECUSpec, SimpleECUSpec, \
    SimpleBusCouplerSpec, SimpleBusSpec
from io_processing.surveillance import Monitor
from io_processing.result_reader import ResultReader
from io_processing.result_interpreter.abst_result_interpreter import InterpreterOptions
from io_processing.result_interpreter.can_bus_interpreter import CanBusInterpreter
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter
from io_processing.result_interpreter.checkpoint_interpreter import CheckpointInterpreter
from io_processing.result_interpreter.buffer_interpreter import BufferInterpreter
from io_processing.surveillance_handler import InputHandlerChain, EventlineHandler  # @UnusedImport
from config.specification_set import LWASpecPresets, GeneralSpecPreset
from components.base.ecu.software.impl_datalink_layers import StdDatalinkLayer, \
    RapidDatalinkLayer
from components.base.ecu.software.impl_transport_layers import StdTransportLayer, \
    FakeSegmentTransportLayer
from components.base.ecu.software.impl_physical_layers import StdPhysicalLayer
from config.timing_db_admin import TimingDBMap

#===============================================================================
#     Define predefined settings
#===============================================================================
LWASpecPresets().preset_ecu = "Crypto_Lib_HW"
LWASpecPresets().preset_sec_mod = "Crypto_Lib_HW"

LWASpecPresets().trigger_spec = [0, 99999999]  # authentication: start time and interval

LWASpecPresets().sec_certificate_spec = [HashMechEnum.MD5, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, 1, 1000]  # security module certificate info

LWASpecPresets().registration_first_part = [AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, 100]  # registration message first part
LWASpecPresets().registration_second_part = [HashMechEnum.MD5, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537]  # registration message second part
LWASpecPresets().ecu_certificate_spec = [HashMechEnum.MD5, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_512, 65537, 1, 1000]  # ecu certificate info

LWASpecPresets().confirmation_part = [100]  # confirmation message size

LWASpecPresets().ecu_key_info = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.ECB]  # ecu key specification
LWASpecPresets().hold_rule = [False, 10]  # hold on/off; minimal interval between two stream requests

LWASpecPresets().request_spec = [100, 9999999999]  # size of request message and timeout maximum

LWASpecPresets().deny_spec = [100]  # deny message size
LWASpecPresets().grant_spec = [100]  # grant message size

LWASpecPresets().session_key_info = [SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, SymAuthMechEnum.ECB]  # session key information

# set further layer specifications
GeneralSpecPreset().enable()
GeneralSpecPreset().physical_layer = StdPhysicalLayer
GeneralSpecPreset().datalink_layer = StdDatalinkLayer  # datalink layer that is used in all ECUs that implement this option
GeneralSpecPreset().transport_layer = FakeSegmentTransportLayer

TimingDBMap().enable_fallback_message = True

#===============================================================================
#     Setting up a project
#===============================================================================

# register ECUs that are located outside of the usual folders
# usual folders: components.base.ecu.types and components.security.ecu.types
api.register_ecu_classes(r"C:\Users\artur.mrowca\workspace\ECUSimulation\components\base\gateways")

# setup the logging
api_log_path = os.path.join(os.path.dirname(__file__), "logs/api.log")
api.show_logging(logging.INFO, api_log_path, True)

# create an empty environment specification for the environment
sim_env = api.create_environment(200)

#===============================================================================
#     Creating ECUs
#=============================================================================== 

# create the ECU specification
ecu_spec = RegularECUSpec(["RegularSecureECU_15"], 20000, 20000)

# adjust the specification
ecu_spec.set_apply_jitter(0.000001)

# further settings can be found in the set_settings method of each component e.g. see RegularSecureECU class
ecu_spec.set_ecu_setting('p_stream_hold', False)
ecu_spec.set_ecu_setting('p_stream_req_min_interval', 5)
LWASpecPresets().apply_spec(ecu_spec, 'ecu')

# for a RegularECUSpec define sending actions of the ECU
ecu_spec.add_sending_actions(10, 0.25, can_registration.CAN_TEST_MSG, "TEST STRING A", 50)
ecu_spec.add_sending_actions(10, 0.5, 16, "TEST STRING B", 50)  # sends at 300, 308, 316, ...

# set the ECU already authenticated
ecu_spec.set_authenticated(True)

# generate a ECU group from the specification
ecu_group_1 = api.set_ecus(sim_env, 1, 'RegularSecureECU', ecu_spec)
 
# create further ECU groups
ecu_spec = RegularECUSpec(["RegularSecureECU_1", "RegularSecureECU_10"], 20000, 20000)
ecu_spec.set_apply_jitter(0.0001)
LWASpecPresets().apply_spec(ecu_spec, 'ecu')
ecu_group_3 = api.set_ecus(sim_env, 2, 'RegularSecureECU', ecu_spec)
 
ecu_spec = RegularECUSpec(["RegularSecureECU_18", "Any_ECU_Name"], 20000, 20000)
ecu_spec.set_apply_jitter(0.0001)
# ecu_spec.set_startup_delay(140)  # start this ecu with delay of 15

LWASpecPresets().apply_spec(ecu_spec, 'ecu')
ecu_group_4 = api.set_ecus(sim_env, 3, 'RegularSecureECU', ecu_spec)
 
#===============================================================================
#     Creating Security modules
#===============================================================================

# create the ECU specification
ecu_spec = SimpleECUSpec(['SEC 1'], 200000, 200000)  # 200 KB

# adjust the specification
ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 0)  
ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 1000)  
ecu_spec.set_apply_jitter(0.0001)
LWASpecPresets().apply_spec(ecu_spec, 'sec_mod')

# create exactly one security module
sec_mod_group = api.set_ecus(sim_env, 1, 'SecLwAuthSecurityModule', ecu_spec)
security_module = sec_mod_group[0]

#===============================================================================
#     Creating Gateways
#===============================================================================

# create the Gateway specification
ecu_spec = SimpleBusCouplerSpec([])

# set gateway delay to 2 seconds
ecu_spec.set_ecu_setting('t_transition_process', 2)

# add a jitter
# ecu_spec.set_apply_jitter(0.000001)

# set a filter
# Add a filter to the gateway. Generally blocks those ids// do not use in combination with api.gateway_filter_bus
# ecu_spec.set_filter(can_registration.AUTH_MESSAGES + [can_registration.CAN_TEST_MSG, 500, 16])

# create the gateway
gateway_group_1 = api.set_ecus(sim_env, 1, 'CANGateway', ecu_spec)

# create another gateway with same specification
gateway_group_2 = api.set_ecus(sim_env, 1, 'CANGateway', ecu_spec)

 
#===============================================================================
#     Creating Busses
#===============================================================================
 
# create the bus specifications
bus_spec = SimpleBusSpec(['CAN_0', 'CAN_1', 'CAN_2'])
bus_group = api.set_busses(sim_env, 3, 'StdCANBus', bus_spec)
 
# Connect ECUs and Gateways to the busses
# Connect CAN 0 via GW1 to CAN 1 // Connect CAN 1 via GW 2 to CAN 2
api.connect_bus_by_obj(sim_env, 'CAN_0', ecu_group_1 + sec_mod_group + gateway_group_1) 
api.connect_bus_by_obj(sim_env, 'CAN_1', gateway_group_1 + ecu_group_3 + gateway_group_2)
api.connect_bus_by_obj(sim_env, 'CAN_2', ecu_group_4 + gateway_group_2)

#===============================================================================
#    Setting a gateway filter: 2 types
#===============================================================================

# type 1 - receive filter: only the defined message ids will be received from the defined bus
# in this example: gateway 1 will only receive message ids 1,2,3,4,5 from CAN_0 - all others are discarded
#                  analogously it only receives message ids 1,2,3,4,5,2730,511 from CAN_1 - all others are discarded
# api.gateway_filter_bus(gateway_group_1, {'CAN_0':[1,2,3,4,5], 'CAN_1':[1,2,3,4,5,2730,511]})  

# type 1 - receive filter: only the defined message ids will be forwarded to the defined bus
# in this example: gateway 1 will only transmit message ids 1, 2, 3, 4, 2730, 5, 6, 7, 8, 9 to CAN_0 - all others are not forwarded to this bus
#                  analogously it only transmits message ids 1, 2, 3, 4, 5, 6, 7, 8, 9, 2730, 511 to CAN_1 - all others are not forwarded to this bus
# api.gateway_filter_sending_bus(gateway_group_1, {'CAN_0':[1, 2, 3, 4, 2730, 5, 6, 7, 8, 9], 'CAN_1':[1, 2, 3, 4, 5, 6, 7, 8, 9, 2730, 511], 'CAN_2':[1, 2, 3, 4, 5, 6, 7, 8, 9, 2730, 511]})  
 
#==============================================================================
#    setup security values of ECUs
#==============================================================================

# register all ECUs to the security module
all_ecu_groups = [ecu_group_1 + ecu_group_3 + ecu_group_4]
api.register_ecu_groups_to_secmod(sim_env, security_module.ecu_id, all_ecu_groups)
 
# generate the certificates for the ECUs
# the constellation of the certificate - i.e. its organization in the CA hierarchy is set
# in the certificate_manager object
certificate_manager = api.create_cert_manager()

# create a certificate signed by CA CAEnum.CA_L313 defined in the CAHierarchy() that was defined in the 
# certificate manager. A custom CAHierarchy can be passed to the api.create_cert_manager() class
all_created_ecus = api.ecu_list_from_groups([all_ecu_groups])
ecu_ids = [ecu.ecu_id for ecu in all_created_ecus]

# generate certificates for the ECUs and setting root certificates to the corresponding security module
for ecu_id in ecu_ids:
    api.generate_valid_ecu_cert_cfg(certificate_manager, ecu_id, CAEnum.CA_L313, security_module.ecu_id, 0, float('inf'))

# generate a certificate in the security module and setting root certificates to all ecus passed in the list ecu_ids
api.generate_valid_sec_mod_cert_cfg(certificate_manager, security_module.ecu_id, CAEnum.CA_L313, ecu_ids, 0, float('inf'))

# apply the certification
api.apply_certification(sim_env, certificate_manager)
 

#===============================================================================
#     Setup the streams
#===============================================================================

# add allowed streams to the to the security module which is responsible for managing requested streams
stream_1 = MessageStream('RegularSecureECU_15', ['RegularSecureECU_1', 'RegularSecureECU_18'], can_registration.CAN_TEST_MSG, float('inf'), 0, float('inf'))
stream_2 = MessageStream('RegularSecureECU_15', ['Any_ECU_Name'], 16, float('inf'), 0, float('inf'))
  
api.add_allowed_stream(sim_env, security_module.ecu_id, stream_1)
api.add_allowed_stream(sim_env, security_module.ecu_id, stream_2)

# this method defines the gateway filter in the following way
# only streams are let pass that are headed in the right direction
# so if a stream with id 60 is defined from E1 at CAN1 and headed to E2 at CAN0 via Gateway G1
# then this message would be filtered out when sent from  CAN0 to CAN1 
# or if a message is heading to E2 that was not declared in the streams it will not be forwarded
# to CAN0 
api.autoset_gateway_filters(sim_env, security_module.ecu_id)
 
#===============================================================================
#     Defining functions called when accessing the timeout values
#===============================================================================

# create mapping from functions onto timing variables 
# e.g. t_ecu_auth_reg_msg_validate_cert should call function my_test_function
#      def my_test_function(*args):
#          ''' do something '''
#      -> function_set.set_mapping('RegularSecureECU_15', 't_ecu_auth_reg_msg_validate_cert', my_test_function)
function_set = TimingFunctionSet()

# create a timing function set for a Security Module
# this mapping contains all mappings from timing variables used in the security module
# to methods that are called when those timings are accessed
# i.e. set a set of functions to a set of timing variables instead of mapping each function seperately
# in this case the timing value is determined from the database by using the key word CyaSSL under
# the library column in the measurements.db database. If another set of measurements was made
# the main_library_tag can be set to the new value
ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag=LWASpecPresets().preset_sec_mod)

# set the function set as mapping to be used
function_set.set_mapping_from_function_set(security_module.ecu_id, ecu_func_set)

# apply this function set now on the specified ECU with the defined id
api.apply_timing_functions_set(sim_env, security_module.ecu_id, function_set)

# optional: as mentioned above the function_set.set_mapping method would override the methods
#           used and defined in the function set


# analogously: do same for all ECUs   
function_set_2 = TimingFunctionSet() 
ecu_func_set = StdSecurECUTimingFunctions(main_library_tag=LWASpecPresets().preset_ecu)
for ecu_id in ecu_ids:
    function_set_2.set_mapping_from_function_set(ecu_id, ecu_func_set) 
    api.apply_timing_functions_set(sim_env, ecu_id, function_set_2)
     


#===============================================================================
#     Save and load the environment from a file (not working yet)
#===============================================================================

# Save environment
# filepath = os.path.join(os.path.dirname(__file__), "environments/1.env")
# api.save_env_spec(sim_env, filepath)  
# sim_env = api.load_env_spec(filepath)
    


#===========================================================================
#     Monitoring and Export of Results
#
#    Structure:
#    environment connected to monitor object
#    monitor object connected to ResultReader object
#    ResultReader publishes data to the Interpreters
#    Interpreters pass the data to connected GUI and/or to Files
#===========================================================================

# create a Monitor and connect it to the environment
monitor = Monitor()
monitor.set_sample_time(0.48)

# connect monitor to environment
api.connect_monitor(sim_env, monitor, 0.5)  

# optional: if only defined handlers should be called when the monitor receives
#           its values, it can be defined as follows which handlers are to be used
#           if not set all handlers will be called 
# only information given in those handlers will be saved all other information is discarded

# input_handler = InputHandlerChain()
# # input_handler.add_handler(CheckpointHandler(monitor._tmp_db, monitor.con))  
# # input_handler.add_handler(CanBusHandler(monitor._tmp_db, monitor.con))
# # input_handler.add_handler(BufferHandler(monitor._tmp_db, monitor.con))
# input_handler.add_handler(EventlineHandler(monitor._tmp_db, monitor.con))  
# input_handler = input_handler.handler()
# monitor.set_handler_chain(input_handler)


# create a Result Reader that is used to export the 
# simulation results to the GUI or to a file
result_reader = ResultReader()
save_path_cp = os.path.join(os.path.dirname(__file__), "logs/checkpoints.csv")
save_path_buf = os.path.join(os.path.dirname(__file__), "logs/buffer.csv")
save_path_can = os.path.join(os.path.dirname(__file__), "logs/can_bus.csv")

# enable certain handlers to define which export has to be made
# a result reader receives the interpreter to be used and the InterpreterOptions enum
# defining how the export should be performed
result_reader.enable_handler(BufferInterpreter, [InterpreterOptions.CONNECTION, InterpreterOptions.CSV_FILE], save_path_buf) 
result_reader.enable_handler(CheckpointInterpreter, [ InterpreterOptions.TIMING_FILE], save_path_cp)
result_reader.enable_handler(EventlineInterpreter, [InterpreterOptions.CSV_FILE], save_path_cp)  # CSV Live Tracking
result_reader.enable_handler(CanBusInterpreter, [InterpreterOptions.CSV_MSG_FILE, InterpreterOptions.CSV_DR_FILE], save_path_can)

# connect the result reader to the monitor
api.connect_result_reader(sim_env, monitor, result_reader)


#===============================================================================
#     Using the GUI
#     ::> if the ECUInteraction project is available the GUI can be used 
#         in the following way
#===============================================================================

# create the direct view 
direct_view = gui.direct_view_window.DirectViewer()

# load saved views
# filepath = r"C:\Users\artur.mrowca\Desktop\aaa.tum"
# direct_view.load_show(['MessageCountViewPlugin', 'EventlineViewPlugin'], filepath)
# sys.exit()
# Create the Viewer and add it 
# available Plugins: BufferViewPlugin, CanBusStateViewPlugin, CanBusViewPlugin, CheckpointViewPlugin, 
#                    ConstellationViewPlugin, ECUMessagesViewPlugin, EventlineViewPlugin, MessageCountViewPlugin
sim_env.gui_lock_sync.acquire()  # optionally ensure thread synchronization
direct_view.run(result_reader, ['EventlineViewPlugin', 'MessageCountViewPlugin'], sim_env.gui_lock_sync)  # optional: sim_env.gui_lock_sync

# creates a button that makes the simulation stop calling on finish for all interpreters
api.open_simulation_stop_button(sim_env)

# build the simulation
api.build_simulation(sim_env)

# run the simulation
api.run_simulation(sim_env)

