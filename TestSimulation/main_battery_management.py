'''
Created on 24 Jul, 2015
This module can only be used together with the battery managementent simulator 
which is not provided within this package.
@author: artur.mrowca
'''
import sys
from tools.general import General
from io_processing.surveillance_handler import EventlineHandler, MonitorTags
from config.specification_set import GeneralSpecPreset
from components.base.ecu.software.impl_datalink_layers import RapidDatalinkLayer
from components.base.bus.impl_rapid_bus_can import RapidCANBus
sys.path.append("../ECUInteraction")
sys.path.append("../ECUSimulation")
sys.path.append("../smart-cell-cps-co-simulator")

from api.core.component_specs import RegularECUSpec
from adapter.security_simulation_adapter import BatManAdministrator
from smartcellsimulator.scripts.startGUI import run
from io_processing.surveillance import Monitor
from io_processing.result_reader import ResultReader
from io_processing.result_interpreter.buffer_interpreter import BufferInterpreter
from io_processing.result_interpreter.checkpoint_interpreter import CheckpointInterpreter
from io_processing.result_interpreter.eventline_interpreter import EventlineInterpreter
from io_processing.result_interpreter.can_bus_interpreter import CanBusInterpreter
from io_processing.result_interpreter.abst_result_interpreter import InterpreterOptions
from gui.direct_view_window import DirectViewer
import os


# rapid mode
ecu_type = "lw_auth"
rapid = True
file_name = "checkpoints_XX_cells.csv"

if rapid:
    General().diabled_buffer_control = True  # disable buffer control (speedup)
    if ecu_type not in ["tls", "tesla"]: General().send_only_to_receivers = True  # Bus will only send to receivers (speedup)
    show_tags = EventlineHandler()._get_tags()
    show_tags.remove(MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE)
    show_tags.remove(MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE)
    General().init_csv_writer(os.path.join(r"D:\Test_runs\bat_man", file_name) , show_tags)
    General().disable_permanent_request = True  # disable permanent request (reduce events)

    

BatManAdministrator().activate_ecu_simulation()

# define the ECU Simulation side of the simulation
ecu_spec = RegularECUSpec([""], 20000, 20000)
ecu_spec.set_apply_jitter(0.000001)
ecu_spec.set_ecu_setting('p_stream_hold', False)
ecu_spec.set_ecu_setting('p_stream_req_min_interval', 5)    

# map ecu specs onto values
BatManAdministrator().set_ecu_spec(ecu_spec, 'BatManAdapterECU')

if not rapid:
    # set monitor
    monitor = Monitor()
    monitor.set_sample_time(0.48)
            
    result_reader = ResultReader()
    save_path_cp = os.path.join(os.path.dirname(__file__), "logs/checkpoints.csv")
    save_path_buf = os.path.join(os.path.dirname(__file__), "logs/buffer.csv")
    save_path_can = os.path.join(os.path.dirname(__file__), "logs/can_bus.csv")
    
    result_reader.enable_handler(BufferInterpreter, [InterpreterOptions.CONNECTION, InterpreterOptions.CSV_FILE], save_path_buf) 
    result_reader.enable_handler(CheckpointInterpreter, [ InterpreterOptions.TIMING_FILE], save_path_cp)
    result_reader.enable_handler(EventlineInterpreter, [InterpreterOptions.CSV_FILE], save_path_cp)  # CSV Live Tracking
    result_reader.enable_handler(CanBusInterpreter, [InterpreterOptions.CSV_MSG_FILE, InterpreterOptions.CSV_DR_FILE], save_path_can)
    
    direct_view = DirectViewer()    
    BatManAdministrator().add_view(direct_view, ['EventlineViewPlugin', 'MessageCountViewPlugin', 'CanBusViewPlugin'])
    
    # add monitor and view        
    BatManAdministrator().connect_monitor_reader(monitor, result_reader)

# start gui 
run()


# 2. CAN Send von denen startet self.sim_env.process(passendeECU.applicatinlayer.send(message))
