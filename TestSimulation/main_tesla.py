#!/usr/bin/env python
'''==================================================================================================
    title:              main.py
    author:             Artur Mrowca
    last modified:      24/07/2015
    usage:              python main_tesla.py  
    python version:     3.0
    description:        this module exemplarily shows the functionality of the ECUSimulation     
                        project for the TESLA (Timed Efficient Stream Loss-Tolerant Authentication)
                        environment as it is defined in RFC 4442 It also describes how the API of 
                        the ECUSimulation should be used. Thereby only new elements will be described. 
                        For the basic usage refer to the main.py module in this project
=================================================================================================='''

import sys

sys.path.append("../ECUSimulation")
sys.path.append("../ECUInteraction")
sys.path.append("../Testcases")

import logging
import os
from api.core.api_core import TimingFunctionSet
import api.ecu_sim_api as api 
import gui.direct_view_window
from api.core.component_specs import SimpleBusCouplerSpec, SimpleBusSpec, RegularECUSpec
from io_processing.surveillance import Monitor
from io_processing.result_reader import ResultReaderfrom components.security.communication.stream import MessageStream
from config import can_registration
from io_processing.result_interpreter.abst_result_interpreter import InterpreterOptions
from io_processing.result_interpreter.checkpoint_interpreter import CheckpointInterpreter
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter
from io_processing.result_interpreter.buffer_interpreter import BufferInterpreter
from io_processing.result_interpreter.can_bus_interpreter import CanBusInterpreter
from components.security.ecu.types.impl_ecu_tesla import StdTeslaECUTimingFunctions

#===============================================================================
#     Setup project, ECUs, Gateways, Busses
#===============================================================================
api_log_path = os.path.join(os.path.dirname(__file__), "logs/api.log")
api.show_logging(logging.INFO, api_log_path, True)

# environment
sim_env = api.create_environment(500)
  
# create ECUs: Attention: for Tesla the sending actions defined in  add_sending_actions() must
#              conform the defined MessageStream objects. i.e. if a MessageStream is defined 
#              that starts sending at time t_0 with a message sending interval of t_int then
#              the exact same sending action has to be put in the add_sending_action() method!
ecu_spec = RegularECUSpec(["RegularSecureECU_15"], 20000, 20000)
ecu_spec.set_apply_jitter(0.0000001)
# ecu_spec.set_ecu_setting('t_prf_for_key_legitimation', 0)  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
# ecu_spec.set_ecu_setting('t_generate_compare_mac', 0)  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
ecu_spec.add_sending_actions(260, 0.1, can_registration.CAN_TEST_MSG, "TEST STRING B", 50)
ecu_group_1 = api.set_ecus(sim_env, 1, 'TeslaECU', ecu_spec)
  
ecu_spec = RegularECUSpec(["TEST ECU 9", "TEST ECU 10"], 20000, 20000)
ecu_spec.set_apply_jitter(0.0000001)
# ecu_spec.set_ecu_setting('t_prf_for_key_legitimation', 0)  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
# ecu_spec.set_ecu_setting('t_generate_compare_mac', 0)  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
ecu_group_3 = api.set_ecus(sim_env, 2, 'TeslaECU', ecu_spec)
 
ecu_spec = RegularECUSpec(["TEST ECU 11", "TEST ECU 12"], 20000, 20000)
ecu_spec.set_apply_jitter(0.0000001)
# ecu_spec.set_ecu_setting('t_prf_for_key_legitimation', 0)  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
# ecu_spec.set_ecu_setting('t_generate_compare_mac', 0)  # NOTE: If this value has a realistic value this is not working or better to say it works with a extreme delay
ecu_spec.add_sending_actions(250, 0.2, can_registration.CAN_TEST_MSG_2, "TEST STRING A", 80)
ecu_group_4 = api.set_ecus(sim_env, 2, 'TeslaECU', ecu_spec)

# create gateways
ecu_spec = SimpleBusCouplerSpec([])
ecu_spec.set_ecu_setting('t_transition_process', 2)
gateway_group_1 = api.set_ecus(sim_env, 1, 'CANGateway', ecu_spec)
gateway_group_2 = api.set_ecus(sim_env, 1, 'CANGateway', ecu_spec)
 
# create buses and connect ECUs
bus_spec = SimpleBusSpec(['CAN_0', 'CAN_1', 'CAN_2'])
bus_group = api.set_busses(sim_env, 1, 'StdCANBus', bus_spec)
api.connect_bus_by_obj(sim_env, 'CAN_0', ecu_group_1 + ecu_group_3 + ecu_group_4) 
# set timing functions
t_set2 = TimingFunctionSet() 
ecu_func_set = StdTeslaECUTimingFunctions(main_library_tag='CyaSSL') 
for ecu in api.ecu_list_from_groups([[ecu_group_1 + ecu_group_3 + ecu_group_4]]):
    t_set2.set_mapping_from_function_set(ecu.ecu_id, ecu_func_set) 
    api.apply_timing_functions_set(sim_env, ecu.ecu_id, t_set2)
     
# Define streams: Attention this definition of MessageStream objects has to be conform with the 
#                 definition of the sending_actions of the ecus. See above
# Note:  the disclosure delay defines the delay with which the message can be verified. Defined in 
#        sending intervals
stream_1 = MessageStream('RegularSecureECU_15', ['TEST ECU 9', 'TEST ECU 10'], can_registration.CAN_TEST_MSG, start_time=160, sending_interval=0.1, disclosure_delay=1)
stream_2 = MessageStream('TEST ECU 11', ['TEST ECU 9'], can_registration.CAN_TEST_MSG_2, start_time=150, sending_interval=0.2, disclosure_delay=1)

api.set_stream(sim_env, stream_1)
api.set_stream(sim_env, stream_2)
    
#===========================================================================
#     Monitoring and Export of Results
#===========================================================================

# Create a Monitor and Reader
my_moni = Monitor()
my_moni.set_sample_time(0.48)
api.connect_monitor(sim_env, my_moni, 0.5)  # Connect monitor to environment
my_reader = ResultReader()

# enable handlers
save_path_cp = os.path.join(os.path.dirname(__file__), "logs/checkpoints.csv")
save_path_cp_2 = os.path.join(os.path.dirname(__file__), "logs/checkpoints2.csv")
save_path_buf = os.path.join(os.path.dirname(__file__), "logs/buffer.csv")
save_path_can = os.path.join(os.path.dirname(__file__), "logs/can_bus.csv")
 
my_reader.enable_handler(BufferInterpreter, [InterpreterOptions.CONNECTION, InterpreterOptions.CSV_FILE], save_path_buf)  # If connected to GUI this step is done automatically by GUI
my_reader.enable_handler(CheckpointInterpreter, [ InterpreterOptions.TIMING_FILE], save_path_cp)
my_reader.enable_handler(EventlineInterpreter, [InterpreterOptions.CSV_FILE], save_path_cp_2)  # CSV Live Tracking
my_reader.enable_handler(CanBusInterpreter, [InterpreterOptions.CSV_FILE], save_path_can)
api.connect_result_reader(sim_env, my_moni, my_reader)  # Connect result reader

#===============================================================================
#     Connect Reader to GUI
#===============================================================================

# Create a GUI and connect it to the monior
direct_view = gui.direct_view_window.DirectViewer()

# available Plugins: BufferViewPlugin, CanBusStateViewPlugin, CanBusViewPlugin, CheckpointViewPlugin, 
#                    ConstellationViewPlugin, ECUMessagesViewPlugin, EventlineViewPlugin, MessageCountViewPlugin
sim_env.gui_lock_sync.acquire()  # optionally ensure thread synchronization
direct_view.run(my_reader, ['EventlineViewPlugin', 'MessageCountViewPlugin'], sim_env.gui_lock_sync)

# start simulation
api.open_simulation_stop_button(sim_env)
api.build_simulation(sim_env)
api.run_simulation(sim_env)




     


