'''
Created on 25 Apr, 2015

This module is the main interface to be accessed by any participant who is
willing to use the simulation. It is meant to hide the complexity behind the
implementation providing a simple to use possibility to access the simulation.
E.g. the GUI will use this API to generate its simulation, as well as to access
it and receive information from it

@author: artur.mrowca
'''

import logging
import sys
import threading
from time import sleep
import tkinter
from tkinter.font import Font
from simpy.events import URGENT
from api.core.component_factories import ECUFactory, BusFactory
from api.core.component_specs import AutomotiveEnvironmentSpec
from components.security.certification.cert_manager import CertificateManager
from components.security.encryption.encryption_tools import EncryptionSize
from config import can_registration
from enums.sec_cfg_enum import SymAuthMechEnum, AuKeyLengthEnum, \
    AsymAuthMechEnum, HashMechEnum
from environment.simulation_param import SimParam
from tools.ecu_logging import ECULogger as L
from tools.general import General as G, General
from tools.singleton import Singleton
from components.security.ecu.software.impl_comm_module_secure import SecureCommModule
import time
# from tools.performance_evaluator import PerformanceEval
class APICore(Singleton):
    
    
    def __init__(self):
        # Load available ECUs/Busses
        ECUFactory().load_classes()
        BusFactory().load_classes()
       
    def add_allowed_stream(self, env, sec_mod_id, new_stream):
        ''' adds defined streams to the environment
            1. sets sterams in security module
            2. sets hw filter with allowed streams in each ecu transceiver
        
            Input:  env:                 AutomotiveEnvironmentSpec:     specification of the Environment
                    sec_mod_id:          string:                        id of security module
                    new_stream:          MessageStream                  Stream that is allowed in this environment
            Output: -
        '''
        
        # Determine streams
        ecu_list = self._ecu_list_from_groups(env.ecu_groups)        
        sec_mod = self._ecu_by_id(sec_mod_id, ecu_list)        
        streams = sec_mod.get_allowed_streams()
        streams.append(new_stream)   
        # print("List size new_stream %s" % len(streams))  
        
        # add mapping to General
        receiver_refs = self._ecu_ref_from_id(ecu_list, new_stream.receivers) 
        General().add_to_three_dict(General().sender_receiver_map, new_stream.sender_id, new_stream.message_id, [r.ecu_id for r in receiver_refs] + [sec_mod_id])
        
        # Set streams in Security Module   
        sec_mod.set_allowed_streams(streams)
        
        # install hardware filter which filters not allowed streams
        for ecu in ecu_list:
            
            # Gateways handled separately
            if str(ecu.__class__) == "<class 'util.CANGateway'>": continue          
            
            # Set HW Filter
            if not self._is_sec_mod(ecu):
                ecu.install_hw_filter(self._get_allowed_streams(ecu.ecu_id, streams) + can_registration.AUTH_MESSAGES)
            else:
                ecu.install_hw_filter(can_registration.AUTH_MESSAGES)
    
    
    def apply_certification(self, env, cert_manager):
        ''' applies the certification specified in the 
            certificate manager object to the environment 
            
            Input:  env:                 AutomotiveEnvironmentSpec:     specification of the Environment
                    cert_manager:        CertificateManager:            entity that holds the certificates for all parties
            Output: -
            '''
        env.cert_manager = cert_manager
        env.apply_certification = True
        
    
    def apply_timing_function_ind(self, env, comp_id, var_name, timing_function_set):
        ''' Applies timing variables to component with id comp_id
            Input:  env:                 AutomotiveEnvironmentSpec: specification of the Environment
                    comp_id:             string                      id of component that gets settings
                    var_name:            string                      name of variable for this setting
                    timing_function_set: TimingFunctionSet:          Set of associations between timing variables and methods
            Output: -
        '''
                
        # Apply set for ECU x only for variable y
        try:
            env.timing_map[comp_id]
        except:
            env.timing_map[comp_id] = {}
        try:
            env.timing_map[comp_id][var_name]
        except:
            env.timing_map[comp_id][var_name] = {}

        env.timing_map[comp_id][var_name] = timing_function_set.timing_map[comp_id][var_name]
                
    
    def apply_timing_functions_set(self, env, comp_id, timing_function_set):
        ''' Applies a set of timing variables to the environment and the 
            component with id comp_id
            
            Input:  env:                 AutomotiveEnvironmentSpec:      specification of the Environment
                    comp_id:             string:                         id of the component
                    timing_function_set: TimingFunctionSet:              Set of associations between timing variables and methods
            Output: -
            '''
        env.timing_map[comp_id] = timing_function_set.timing_map[comp_id]
                  
    
    def autoset_gateway_filters(self, env, sec_id):
        ''' depending on the allowed streams this method
            sets a filter to each gateway, so that only 
            allowed streams defined in the ecu with sec_id 
            are forwarded
            Input:  env:                   AutomotiveEnvironmentSpec:  specification of the Environment
                    sec_id:                string:                     Id of security module
            Output: -
        '''
        env.autoset_gateway_filters += [sec_id]
                
    
    def build_sim_param(self, env):
        ''' all specification that has been passed to the
            AutomotiveEnvironmentSpec object env will be build 
            in this stage
            
            Input:  env:                 AutomotiveEnvironmentSpec:     specification of the Environment
            Output: -
        '''        

        # Initial parameters
        env.sim_param = SimParam(); L().log(202, env.id)
        env.sim_param.app_lifetime = env.app_lifetime

        # add ECUs
        ecu_list = self._add_all_ecus(env)        

        # add Busses
        bus_dict = self._add_all_busses(env)          
        
        # apply specified timing
        components = ecu_list + list(bus_dict.values())
        self._apply_timing(env, components)
        
        # connect Ecus to Busses
        self._connect_busses(env, ecu_list, bus_dict, env.bus_connections)
        
        # add Certificates if defined  
        self._set_certification(env)      
        
        # set filters for the gateway
        if env.autoset_gateway_filters:
            for sec_id in env.autoset_gateway_filters: 
                self._autoset_gateway_filters(env, sec_id)
        
        # log settings
        try:
            self._log_initial_settings(env)
        except:
            pass
        
        # verify user input depending on ecus
        self._verify_user_input_lwa(env)
        
        
    
    def cert_manager(self, ca_hierarchy):
        ''' 
            creates a certificate manager object from 
            a CAHierarchy object 
            
            Input:  ca_hierarchy:                  CAHierarchy:            Hierarchy of Certification Authorities
            Output: cert_manage                    CertificateManager      entity that holds the certificates for all parties
        '''        
        return CertificateManager(ca_hierarchy)

    
    def connect_bus(self, env, bus_id, lst_add_ids):
        ''' 
            adds all ECUs with ids in lst_add_ids to
            the elements that will be connected to the 
            Bus with Bus ID bus_id    
            
            Input:  env:               AutomotiveEnvironmentSpec:          specification of the Environment
                    bus_id:            string:                             id of the bus to be connected
                    lst_add_ids:       list of strings                     list of ids of AbstractECU instances that will be connected to the bus
            Output: -
        '''        
        for add_id in lst_add_ids:
            env.bus_connections.append([bus_id, add_id])
            
    
    
    def connect_bus_obj(self, env, bus_id, new_obj_list):
        ''' 
            adds all ECU objects in lst_add_obj to
            the elements that will be connected to the 
            Bus with Bus ID bus_id    
            
            Input:  env:               AutomotiveEnvironmentSpec:         specification of the Environment
                    bus_id:            string                             id of the bus to be connected
                    new_obj_list:      list of AbstractECU objects        list of AbstractECU objects
            Output: -
        '''       
        
        for new_obj in new_obj_list:
            new_id = new_obj.ecu_id            
            env.bus_connections.append([bus_id, new_id])
        
    
    def connect_monitor(self, env, monitor, t_period):
        ''' connects a monitor to the environment. All ECUs and 
            Busses that are monitorable are then added to it. 
            All elements that have subscribed to the monitor will get the 
            information once in the time interval t_period. Then the monitor
            publishes all gathered information.
            
            Input:  env:                AutomotiveEnvironmentSpec:         specification of the Environment
                    monitor:            Monitor                            monitor object that obtains information from environment
                    t_period:           float                              sampling time in which the monitor will request information from the environment
            Output: -
        '''
        
        # set properties
        env.monitor = monitor
        env.monitor.set_period(t_period)
        
        # ECUs to monitor
        ecu_list = self._ecu_list_from_groups(env.ecu_groups)
        for ecu in ecu_list:
            monitor.connect(ecu)

        # Busses to monitor
        for bus in env.busses:
            monitor.connect(bus[0])
    
        
    def connect_result_reader(self, env, monitor, reader):
        ''' connects a monitor to a ResultReader, which is 
            used to extract information from the simulation.
            
            Input:  env:               AutomotiveEnvironmentSpec:          specification of the Environment
                    monitor:           Monitor                             monitor object that obtains information from environment
                    reader:            ResultReader                        result reader that will get the monitor values relevant for him forwarded
            Output: -     
        '''
        reader.set_monitor(monitor)
        env.result_reader = reader
    
    
    def create_environment(self, app_lifetime):
        ''' create the automotive environment specification
            that is used to generate a valid environment
            
            Input:  app_lifetime:       float                                lifetime of the application environment
            Output: env:                AutomotiveEnvironmentSpec:           specification of the Environment       
        '''
        return AutomotiveEnvironmentSpec(app_lifetime)
    
      
    def ecu_list_from_groups(self, ecu_groups):
        ''' returns all AbstractECU objects that are specified in the 
            ecu_groups as list
        
            Input:  ecu_groups:         list:              [ ecu_group_1, ecu_group_2,...]  with ecu_group_i = [ecu_list_1, ecu_list_2,...], 
                                                                                            with ecu_list_i = [abstract_ecu_1, abstract_ecu_2,...]     
            Output: ecu_list            list:                list of AbstractECUs
        '''
        return self._ecu_list_from_groups(ecu_groups)
    
    
    def gateway_filter_bus(self, gateway_group, can_dict):
        ''' Sets a fixed filter to the gateway. The can_dict contains
            CAN IDs as keys and a list of allowed message ids as values. 
            Thus all allowed messages will be forwarded and the remaining once
            will be blocked
            e.g. api.gateway_filter_bus(gateway_group_1, {'CAN_0':[2,3,4], 'CAN_1':[5,6,7]})  
                 this filter would act as follows. If a message with either 2,3,4 arrives
                 through CAN_0 to the gateway it will be forwarded. Any other message arriving
                 on that bus will be discarded. Analogously messages 5,6,7 arriving over CAN_1
                 will be forwarded and others not
            
            Input:  gateway_group:   list                    list of Gateway objects
                    can_dict:        dictionary:             key: can id value: list of message ids
            Output: -   
        '''
        for gateway in gateway_group:
            gateway.set_filter_from_can_dict(can_dict)
    
          
    def gateway_filter_sending_bus(self, gateway_group, can_dict):
        ''' Sets a fixed filter to the gateway. The can_dict contains
            CAN IDs as keys and a list of allowed message ids as values. 
            Thus all allowed messages will be forwarded and the remaining once
            will be blocked
            e.g. api.gateway_filter_sending_bus(gateway_group_1, {'CAN_0':[2,3,4], 'CAN_1':[2, 5,6,7]})  
                 this filter would act as follows. If a message with either 2  arrives
                 on any port of the gateway it will be forwarded to CAN_0  and CAN_1. If 3,4 arrives on 
                 any port it will be forwarded to CAN_0 only. etc 
            
            Input:  gateway_group:   list                    list of Gateway objects
                    can_dict:        dictionary:             key: can id value: list of message ids
            Output: -   
        '''
        for gw in gateway_group:
            gw.set_transmit_filter_from_can_dict(can_dict)   

                   
    def generate_valid_ecu_cert_cfg(self, cert_manager, ecu_id, ca_id, sec_mod_id, valid_from, valid_till):
        ''' the security module with id sec_mod_id gets a valid root certificate list 
            for the ECU with id ecu_id
            So the Security Module can verify the ECU's authenticity
            
            Input:  cert_manager:      CertificateManager      entity that holds the certificates for all parties
                    ecu_id:            string
                    ca_id:             string/CAEnum
                    sec_mod_id:        string
                    valid_from:        number
                    valid_till:        number
            Output: -        
        '''
        cert_manager.generate_valid_ecu_cert_cfg(ecu_id, ca_id, sec_mod_id, valid_from, valid_till)
    
        
    def generate_valid_sec_mod_cert_cfg(self, cert_manager, ca_id, sec_mod_id, ecu_id_list, valid_from, valid_till):
        ''' all ECUs that are given in the ecu_id_list will get a valid list of root certificates
            to be able to verify the Security modules authenticity
            
            Input:  cert_manager:      CertificateManager        entity that holds the certificates for all parties
                    ca_id:             string/CAEnum             Id of the Certification Authority that authorizes this certificate
                    sec_mod_id:        string                    id of the security module
                    ecu_id_list:       list of string            list of ecu ids 
                    valid_from:        number                    certificate validity start time
                    valid_till:        number                    certificate validity end time
            Output: -        
        '''
        cert_manager.generate_valid_sec_mod_cert_cfg(sec_mod_id, ca_id, ecu_id_list, valid_from, valid_till)
       
    def open_simulation_stop_button(self, env):
        ''' starts a seperate thread that opens a stop button that 
            can be used to interrupt the simulation without closing the GUI
            and finishing the automotive Environment and simpy Process
            
            Input:    env:            AutomotiveEnvironmentSpec: specification of the Environment
            Output:     -
            '''
        
        try:
            # Create and start Thread
            stop_thread = StoppableThread(env.auto_environment.get_env())
            stop_thread.start()
            env.but_thread = stop_thread
            
        except (KeyboardInterrupt, SystemExit):
            # Finish the process cleanly
            stop_thread.join()
            sys.exit()

        
    def register_bus_classes(self, class_path):
        ''' all AbstractBus classes that are present in the folder
            class_path will be createable within the environment
            
            Input:  class_path:      string        path to the classes that will be creatable
            Output: -     
        '''
        BusFactory().register_path(class_path)
    
        
    def register_ecu_classes(self, class_path):
        ''' all AbstractECU classes that are present in the folder
            class_path will be createable within the environment
            
            Input:  class_path:      string        path to the classes that will be creatable
            Output: -     
        '''
        ECUFactory().register_path(class_path)
        
      
    def register_ecu_groups_to_secmod(self, env, sec_mod_id, ecu_groups):
        ''' in order for the security module to know about the ecus existence
            it is necessary to connect the ECU to the security module 
            
            Input:  env:               AutomotiveEnvironmentSpec:            specification of the Environment
                    sec_mod_id:        string                                id of the security module
                    ecu_groups:        list                                  list of ecu object lists: [[ecu_obj_1, ecu_obj_2, ...], [ecu_obj_12, ecu_obj_13, ...], ...]
            
            Output: -
        '''
        try:
            env.sec_mod_ecu_register[sec_mod_id] += ecu_groups
        except:
            env.sec_mod_ecu_register[sec_mod_id] = ecu_groups
    
          
    def run_simulation(self, env):
        ''' this method starts the actual environment by first creating a 
            simulation parameter and then starting the environment from 
            that created parameter

            Input:  env:           AutomotiveEnvironmentSpec:     specification of the Environment
            Output: - 
        '''
        
        # wait for GUI
        env.gui_lock_sync.acquire()

        # setup automotive environment
        env.auto_environment.setup_from_sim_param(env.sim_param)
        
        # push initial constellation (if monitor defined)
#         from pympler import summary, muppy
        
        try: env.monitor.push_constellation(env.ecu_groups, env.busses, env.bus_connections)
        except: pass  
        
        # start with or without monitor
        start_time = time.time()
        if env.monitor: env.auto_environment.start(env.monitor)        
        else: env.auto_environment.start()
        end_time = time.time()
        print("Time elapsed: %s seconds" % (end_time - start_time))

            
        # call on finish methods to finalize exports
        if env.result_reader != None: env.result_reader.on_finish()
              
        # Stop button thread
        self._handle_stop_button_thread(env)
        
        # memory
#         from scripts.memory_display import get_memory_usage
        
#         usg = get_memory_usage()
#         print("MEMORY USED: %s" % usg)
        # Notify end
        env.gui_lock_sync.release()
        raise SystemExit
        
    def set_app_lifetime(self, env, app_lifetime):
        ''' sets the lifetime of the application
            
            Input:  env:           AutomotiveEnvironmentSpec: specification of the Environment
            Output: - 
        '''
        env.app_lifetime = app_lifetime
        
                      
    def set_busses(self, env, nr_elements, bus_type_id, bus_spec):
        ''' given the bus_type that has to be generated and the bus_spec
            object that is necessary to create the object this method sets
            number nr_elements Busses of that type into the environment
                
            Input:  env:                AutomotiveEnvironmentSpec:          specification of the Environment
                    nr_elements:        int                                 number of busses to be added
                    bus_type_id:        string                              class name of the Bus to be created as string
                    bus_spec:           BusSpec                             specifies behaviour and settings of the generated bus
            
            Output: subset_busses:      List of AbstractBus objects         instances of the created busses
        
        '''
        # Initialize
        subset_busses = []
        for i in range(nr_elements):   
            
            # Generate name                     
            pot_name = self._generate_name_from_idlist(bus_spec.bus_id_list, bus_type_id, env.bus_ids, i)
            
            # generate bus
            constructor_in = [env.auto_environment.get_env(), pot_name, None] + bus_spec.constr_params             
            new_bus = BusFactory().make(bus_type_id, constructor_in)
            
            # save bus
            env.busses.append([new_bus, bus_spec])
            subset_busses.append(new_bus)        
        return subset_busses
            
              
    def set_ecus(self, env, nr_elements, ecu_type_id, ecu_spec):
        ''' adds a certain number of ecus of a certain type with settings 
            defined in ecu_spec to the environment. 
            
            Input:  env:                 AutomotiveEnvironmentSpec:         specification of the Environment
                    nr_elements:         int                                number of ECUs to be added
                    ecu_type_id          string                             class name of the AbstractECU to be created as string
                    ecu_spec             AbstractECUSpec                    AbstractECUSpec that specifies the settings for this group of ECUs
            Output: ecu_group            List of AbstractECU objects        instances of created ECUs
        '''
        # Initialize
        ecu_group = []        
        for i in range(nr_elements):       
                             
            # Generate name                  
            pot_name = self._generate_name_from_idlist(ecu_spec.ecu_id_list, ecu_type_id, env.ecu_ids, i)
            
            # generate ECU object
            constructor_in = [env.auto_environment.get_env(), pot_name, None] + ecu_spec.constr_params 
            
            # save ECU object
            ecu_group.append(ECUFactory().make(ecu_type_id, constructor_in))       
            
            # Set authenticated if specified and applicable
            try: ecu_group[-1].set_authenticated(ecu_spec.is_authenticated)
            except: pass
             
        env.ecu_groups.append([ecu_group, ecu_spec])        
        return ecu_group

    
    def set_stream(self, env, new_stream):
        ''' sets streams for the TLS implementation specifying the receivers for 
            a message with a certain message id
            
            Input:  env:                   AutomotiveEnvironmentSpec: specification of the Environment
                    new_stream:            MessageStream
            Output: -
        '''
        ecu_list = self._ecu_list_from_groups(env.ecu_groups)        
        for ecu in ecu_list:
            try:
                ecu.add_stream(new_stream)
            except:
                pass

      
    def _add_all_busses(self, env):
        ''' adds all busses to the environment that have been
            specified via the API and returns the added elements as
            a dictionary: Bus ID to AbstractBus instance
            
            Input:  env:                 AutomotiveEnvironmentSpec:     specification of the Environment                    
            Output: bus_dict:            dictionary                     key: bus identifier value: instance of the bus object
        '''
        
        bus_dict = {}
        for env_bus in env.busses:  
                
            # extract       
            bus = env_bus[0]
            bus_spec = env_bus[1]
            
            # configure
            self._configure_bus(env, bus, bus_spec); L().log(201, env.id, bus.__class__.__name__, bus.comp_id)     
            bus_dict[bus.comp_id] = env.sim_param.add_bus(bus)
            
        return bus_dict
    
      
    def _add_all_ecus(self, env):
        ''' adds all ECUs to the environment that have been
            specified via the API and returns the added elements as
            a list of ECU instances
            
            Input:  env:                 AutomotiveEnvironmentSpec:         specification of the Environment                    
            Output: ecu_list:            List                               list of AbstractECUs that are added to the environment  
        '''
        
        ecu_list = []
        for ecu_group in env.ecu_groups:
            # extract     
            ecus = ecu_group[0]
            ecu_specs = ecu_group[1]
            
            # configure
            for ecu in ecus:                
                self._configure_ecu(env, ecu, ecu_specs); L().log(200, env.id, ecu.__class__.__name__, self._id_from_component(ecu))   
                ecu_list.append(env.sim_param.add_ecu(ecu)) 
                
        return ecu_list
        
      
    def _add_to_dict(self, da_dict, key_1, key_2, val):
        ''' adds a value enctr val to the dictionary that is in another 
            dictionary, where key_1 and key_2 will be used as keys            
            e.g. dic = {} -> _add_to_dict( dic, 'k1', 'k2', 10) -> dic = {'k1':{'k2':10}}
            
            Input:  da_dict:            dictionary
                    key_1:              object/string/number/...
                    key_2:              object/string/number/...    
                    val:                object/string/number/...    
            Output: - 
        '''
        try:
            da_dict[key_1]
        except:
            da_dict[key_1] = {}
        da_dict[key_1][key_2] = val
        
                  
    def _apply_certification(self, env):
        ''' exchanges the previously defined certificates between the
            specified ECUs and the security module
        
            Input:  env:                AutomotiveEnvironmentSpec: specification of the Environment
            Output: -
        '''
        
        # extract groups
        cert_manager = env.cert_manager
        ecus = self._ecu_list_from_groups(env.ecu_groups)        
        sec_mods = self._filter_sec_mods(ecus, True)
        pure_ecus = self._filter_sec_mods(ecus, False)
        
        # Set Sec Module Certificate
        for ecu in sec_mods:   
            ecu.set_security_set_from_rm(cert_manager)
        
        # Set the ECU Certificates
        for ecu in pure_ecus:
            G().do_try(ecu, 'set_security_set_from_rm', cert_manager)
    
      
    def _apply_gateway_filter(self, ecu, ecu_specs):
        ''' applies a filter that filters out all message IDs
            that are not listed in the ecu_specs object. This
            is done only if the specified object is indeed a 
            Gateway.
            
            Input:  ecu:                CANGateway                      gateway object that will be set up with the filter
                    ecu_specs:          SimpleBusCouplerSpec            Specification of the settings
            Output: -
        '''
        if self._is_gateway(ecu):
            if ecu_specs.allowed_msg_ids:
                ecu.install_filter(ecu_specs.allowed_msg_ids)
    
      
    def _apply_settings_mapping(self, ecu, ecu_specs):
        ''' all settings that were specified in the ecu_specs
            object are applied here by mapping the mapping variable
            to the actual variable path.
            
            Input:  ecu:                AbstractECU                ECUs that are set up
                    ecu_specs:          AbstractECUSpec            Specification of the settings
            Output: -
            '''
        
        # initialize
        settings_dict = ecu.settings        
        if not hasattr(ecu_specs, 'timing_map_vals'): return       
         
        # iterate over variables
        for ky in ecu_specs.timing_map_vals.keys():
            
            # try to set the value
            val = ecu_specs.timing_map_vals[ky]  # @UnusedVariable
            try:
                pat = settings_dict[ky]
            except:
                L().log_err(202, ky)
                continue
            try:
                exec('ecu.' + pat + ' = val')
            except:
                L().log_err(202, ky)
    
      
    def _apply_timing(self, env, comp_list):
        ''' this method assignes the specified functions to the
            specific variables within the components. 
            e.g. 't_reg_msg_sym_keygen' was defined in the SecureECU object settings
                 and in the function map of the StdSecurECUTimingFunctions object which was
                 applied via the API also contains a entry for 't_reg_msg_sym_keygen'
                 Then the value defined for this function_map entry will be used when the 
                 variable is accessed
            Note: If a constant value was assigned to this setting via the API then the constant
                  value will be used when the variable is accessed
                 
            Input:  env:                AutomotiveEnvironmentSpec:           specification of the Environment
                    comp_list:          list                                 List of Components: AbstractECUs, AbstractBuses, 
            Output: -
        
        '''
        # iterate over components
        for component in comp_list: 
                        
            try:                
                # Load timing mapping
                comp_id = self._id_from_component(component)
                timing_dict = env.timing_map[comp_id]
                
                # set corresponding setting
                for variable_id in timing_dict.keys():
                    try: self._set_setting(component, variable_id, timing_dict[variable_id])
                    except: L().log_info_traceback(208, component, variable_id)                        
                    
                # override constant values
                ecu_spec = self._ecu_spec_by_id(component.ecu_id, env.ecu_groups)
                self._apply_settings_mapping(component, ecu_spec)

            except:
                L().log_info(209, component)                
    
    
    def _autoset_gateway_filters(self, env, sec_id): 
        ''' sets a filter on every gateway that only lets through Streams 
            in the directions with the allowed ECUs hanging on the connected Bus:
            e.g. constellation:     ECU_1 - CAN_1 -ECU_2
                                              |
                             ECU_4 - CAN_3 - GW_1 - CAN_2 - ECU_3
                                                     |
                                                   Sec_Module
                                                   
                                    Streams allowed: ECU_1 sends to ECU_4 with Stream ID 12
                  solution: this method will allow only flows from CAN_1 to CAN_3 that have Stream ID 12
                            the stream in the opposite direction will be ignored. 
                            Moreover all streams requiring communication with the security module are
                            let through by the Gateway
            
            Input:  env:                 AutomotiveEnvironmentSpec:          specification of the Environment
                    sec_id:              string:                             id of the security module
            Output: -
        
        '''
        ecu_list = self._ecu_list_from_groups(env.ecu_groups)        
        sec_mod = self._ecu_by_id(sec_id, ecu_list)        
        streams = sec_mod.get_allowed_streams()        
        gateway_dict = {}
        gateway_dict_forward = {}
        
        # Authentication allowed + Streams defined
        for stream in streams:
            start_bus = self._bus_by_ecu_id(env, stream.sender_id)            
            for rec_id in stream.receivers:
                dest_bus = self._bus_by_ecu_id(env, rec_id)
                if dest_bus != None:
                    comp_path = self._path_from_busses(env, start_bus, dest_bus, None)  # ['CAN_0', 'GW_1', 'CAN_1', 'GW_2', 'CAN_2']
                    if comp_path == None: return

                    # set all Gateway filter along the way
                    cur_id = None
                    for comp in comp_path:
                        # Bus
                        if not self._is_gateway(comp): 
                            cur_id = comp.comp_id
                            continue
                        
                        # Gateway: add ids and bus to be added
                        G().force_add_dict_list_2(gateway_dict, comp.ecu_id, cur_id, stream.message_id, sys.maxsize)
        

                    # Gateway: add ids forward
                    for comp in comp_path[::-1]:
                        # Bus
                        if not self._is_gateway(comp): 
                            cur_id = comp.comp_id
                            continue
                        
                        # Gateway: add ids and bus to be added                        
                        G().force_add_dict_list_2(gateway_dict_forward, comp.ecu_id, cur_id, stream.message_id, sys.maxsize)
        
                        
        # Found all forward filters
        
        
        # Set all found backward filters 
        ecu_list = self._ecu_list_from_groups(env.ecu_groups)
        for gw in ecu_list:
            if gw.ecu_id in gateway_dict:
                # Add authentication messages
                for auth_id in can_registration.AUTH_MESSAGES:
                    for bus in gw._connected_busses:
                        G().force_add_dict_list_2(gateway_dict, gw.ecu_id, bus.comp_id, auth_id, sys.maxsize)
                        G().force_add_dict_list_2(gateway_dict_forward, gw.ecu_id, bus.comp_id, auth_id, sys.maxsize)
                        
                    
                set_dict = gateway_dict[gw.ecu_id]    
                set_dict_fw = gateway_dict_forward[gw.ecu_id]       
                self.gateway_filter_bus([gw], set_dict)
                self.gateway_filter_sending_bus([gw], set_dict_fw)
        
    
    def _bus_by_id(self, env, bus_id):
        ''' returns the bus with id bus_id from the 
            environment if it is defined. Else returns
            None
            
            Input:  env:                AutomotiveEnvironmentSpec:     specification of the Environment
                    bus_id:             string                         identifier of the Bus object
            Output: bus                 CANBus                         Can bus object with id bus_id
        '''
        for bus in env.busses:
            if bus[0].comp_id == bus_id:
                return bus[0]
        return None
        
    
    def _bus_by_ecu_id(self, env, ecu_id):
        ''' returns the bus that the ECU with id ecu_id is
            connected to
        
            Input:  env:                AutomotiveEnvironmentSpec:     specification of the Environment
                    ecu_id:             string                         identifier of the respective ECU
            Output: bus                 CANBus                         bus object that is connected to the given ECU with ecu_id
        '''
        for con in env.bus_connections:
            if con[1] == ecu_id:
                bus_id = con[0]
                bus = self._bus_by_id(env, bus_id)
                return bus
        return None
        
      
    def _configure_bus(self, env, bus, bus_spec):
        '''
        called on every bus that is added to the environment. 
        Currently this method is not implemented
        Input:  env:                AutomotiveEnvironmentSpec:           specification of the Environment
                bus                 CANBus object                        object to be configured
                bus_spec            AbstractBusSpec                      specification of the bus object
            
        Output: -
        '''
        pass
    
      
    def _configure_ecu(self, env, ecu, ecu_specs):
        '''
        called on every ECU that is added to the environment. 
    
        
        Input:  env:                AutomotiveEnvironmentSpec:           specification of the Environment
                ecu                 AbstractECU                          object to be configured
                ecu_specs           AbstractECUSpec                      specification of the ECU object
            
        Output: -
        '''      
        # set startup delay
        self._set_startup_delay(ecu, ecu_specs)
        
        # configure RegularEcuSpec (optional)
        self._configure_regular_sec_ecu(ecu, ecu_specs)
                
        # set settings mapping 
        self._apply_settings_mapping(ecu, ecu_specs)
            
        # add filter to Gateway (optional)
        self._apply_gateway_filter(ecu, ecu_specs)

        # set jitter values
        self._set_jitter(ecu, ecu_specs)        

        # Register Ecus to security module (optional)
        self._register_ecus_to_sec_mod(env, ecu, ecu_specs)
    
      
    def _configure_regular_sec_ecu(self, ecu, ecu_specs):
        ''' sets the sending actions and special configurations for a 
            ECU that has a RegularApplicationLayer
            
            Input:  ecu                 AbstractECU                          object to be configured
                    ecu_specs           AbstractECUSpec                      specification of the ECU object
            Output: -
        '''
        
        try:
            # add sending actions
            for action in ecu_specs.sending_actions:
                try: ecu.add_sending(action[0], action[1], action[2], action[3], action[4])
                except: pass
                
        except:
            pass
    
        
    def _connect_busses(self, env, ecu_list, bus_dict, bus_connections):
        ''' connects the previously defined AbstractECUs in the ecu_list to
            the defined busses in bus_dict.         
        
            Input:  env:                AutomotiveEnvironmentSpec:              specification of the Environment
                    ecu_list            list                                    list of AbstractECUs                          
                    bus_dict            dictionary                              association from bus id to bus object
                    bus_connection      list                                    list of associations between ECU Ids and Bus Ids to be connected 
            Output: -
        '''
        
        for bus_connection in bus_connections:
            
            # obtain information
            bus_id = bus_connection[0]
            ecu_id = bus_connection[1]            
            L().log(203, ecu_id, bus_id)
            ecu = self._ecu_by_id(ecu_id, ecu_list)                        
            
            # connect objects
            env.sim_param.connect(bus_dict[bus_id], ecu)

      
    def _ecu_by_id(self, ecu_id, ecu_list):
        ''' returns the AbstractECU object in the provided
            ecu_list by its id
            
            Input:  ecu_id:             string:              id of the AbstractECU
                    ecu_list            list                 list of AbstractECUs                         
                    
            Output: ecu                 AbstractECU          object with id ecu_id
        '''        
        for ecu in ecu_list:
            if ecu.ecu_id == ecu_id:
                return ecu
        return None
    
      
    def _ecu_list_from_groups(self, ecu_groups):
        ''' returns all AbstractECU objects that are specified in the 
            ecu_groups as list
        
            Input:  ecu_groups:         list:              [ ecu_group_1, ecu_group_2,...]  with ecu_group_i = [ecu_list_1, ecu_list_2,...], 
                                                                                            with ecu_list_i = [abstract_ecu_1, abstract_ecu_2,...]     
            Output: ecu_list            list:                list of AbstractECUs
        '''
        ecu_list = []
        for ecu_group in ecu_groups: 
            ecus = ecu_group[0]
            for ecu in ecus:  
                ecu_list.append(ecu)                 
        return ecu_list
    
      
    def _ecu_ref_from_id(self, ecu_list, ecu_ids):
        ''' This method returns references to all 
            ecus that are in the list ecu_ids
            
            Input:  ecu_list    list    list with AbstractECU objects
                    ecu_ids     list    list of ecu ids
            Output: ref_list    list    list of Abstract ECU objects
        '''
        
        ref_list = []
        for ecu in ecu_list:            
            if ecu.ecu_id in ecu_ids:
                if ecu not in ref_list:
                    ref_list.append(ecu)
        return ref_list
      
    def _ecu_spec_by_id(self, ecu_id, ecu_groups):
        ''' returns the corresponding AbstractECUSpec from a given group of
            AbstractECUs
        
        
            Input:  ecu_id:             string:               id of the AbstractECU
                    ecu_groups:         list:                 [ecu_group_1, ecu_group_2,...]  with ecu_group_i = [ecu_list, ecu_spec], 
                                                                                              with ecu_list_i = [abstract_ecu_1, abstract_ecu_2,...]                         
                    
            Output: ecu_specs           AbstractECUSpec        Specs for ECU with id ecu_id
        
        '''
        for ecu_group in ecu_groups: 
            ecus = ecu_group[0]
            ecu_specs = ecu_group[1]
            for ecu in ecus:                
                if ecu.ecu_id == ecu_id:
                    return ecu_specs
        
          
    def _filter_sec_mods(self, ecus, mode):
        ''' If the variable mode is True:
                returns all ecus that are a Security modules
            
            If the variable mode is False:
                returns all ecus that are not a Security modules
            
            Input:  ecus:                List                List of AbstractECU objects
                    mode:                boolean             specifying the mode of this method
            Output: out_lst            
        '''
        
        out_list = []
        for ecu in ecus:
            
            # add if security module
            if self._is_sec_mod(ecu):
                if mode: out_list.append(ecu)
            
            # add if not security module    
            else:
                if not mode: out_list.append(ecu)
                
        return out_list
        
      
    def _generate_name_from_idlist(self, id_list, type_id, ids, i):
        ''' generates a consistent name, avoiding name conflicts
            from the currently forgiven names and optionaly provided ids
            If no ids were provided standard notation will be used
            
            Input:  id_list:             list:              optional list of ids that will be used as names (in given order)
                    type_id:             string:            class name of the object type that will get a name generated
                    ids                  list               list of ids
                    i                    int                index indicating the current element in the id_list that is under consideration
                    
            Output: pot_name             string              name for the current component
            
        '''
        if id_list: 
            try:                    
                pot_name = id_list[i]
            except:
                pot_name = type_id + "_" + str(i) 
        else: pot_name = type_id + "_" + str(i)                
        new_name = False
        k = 0
        while not new_name:                
            if pot_name not in ids:
                new_name = True
                ids.append(pot_name)
                break
            pot_name = type_id + "_" + str(k) 
            k += 1
            
        return pot_name
    
      
    def _get_allowed_streams(self, ecu_id, streams):
        ''' returns all streams were the given ecu_id is 
            a valid receiver
            
            Input:  ecu_id:              string:              Id of the AbstractECU that is under consideration
                    streams:             list:                list of MessageStream objects                    
            Output: allowed              list:                list of MessageStreams
        
        '''
        allowed = []
        for stream in streams:
            if ecu_id in stream.receivers:
                if stream.message_id not in allowed:
                    allowed.append(stream.message_id)
        return allowed
        
        
    def _get_setting_val(self, component, variable):
        ''' returns the value of a components setting from its 
            given variable
            e.g. 't_reg_msg_sym_keygen' is given as variable and a TLSECU 
                 object. Then the current value on which 't_reg_msg_sym_keygen' is
                 mapped on will be returned
                 
            Input:  component:            AutomotiveComponent:               object under consideration
                    variable:             string:                            settings id to be evaluated
            Output: result:               object/string/number/...           value of the provided setting
        '''
        try:
            value = component.settings[variable]
            execution_str = 'component.' + value 
            result = eval(execution_str)  
            return result
        except:
            return 0
        
    
    def _handle_stop_button_thread(self, env):
        ''' When the main thread finishes this method ensures that
            the thread in which the stop button is running is finalized
            correctly and it also ensures that the thread is kept alive
            while the GUI is still working
        
            Input:  env:            AutomotiveEnvironmentSpec:           specification of the Environment
            Output: -  
        
        '''
        
        try:
            # thread ended by button do nothing (to keep gui alive)
            if env.but_thread.button_end:
                while True:
                    sleep(5)
                return
            env.but_thread.root.focus_force()
            env.but_thread.root.quit()
            env.but_thread.join()
        except:
            pass
        
      
    def _id_from_component(self, component):
        ''' Determines the component id from the 
            component
            
            Input:  component:           AutomotiveComponent:          object under consideration
            Output: comp_id:             string                        component id of the given component
             '''
        try: 
            comp_id = component.ecu_id
        except: 
            comp_id = component.comp_id
        return comp_id
        
      
    def _is_gateway(self, ecu):
        ''' returns true if the passed AbstractECU object
            is a Gateway else returns False
            
            Input:  ecu:                AbstractECU                object under consideration
            Output: val                 boolean                    true if the provided ECU is a Gateway
        '''
        try:   
            ecu._GATEWAY
            return True              
        except:
            pass
        return False
    
      
    def _is_sec_mod(self, ecu):
        ''' returns true if the passed AbstractECU object
            is a SecurityModule else returns False
            
            Input:  ecu:                AbstractECU                object under consideration
            Output: val                 boolean                    true if the provided ECU is a Security Module    
        '''
        try:   
            ecu._SECMODULE
            return True              
        except:
            pass
        return False
    
         
    def _log_initial_settings(self, env):
        ''' logs all settings that are initially defined in the current
            environment (in AbstractECUs and Busses)
        
            Input:  env:            AutomotiveEnvironmentSpec:           specification of the Environment
            Output: -  
        '''
        L().log(204)
        
        # log all ecu settings
        ecu_list = self._ecu_list_from_groups(env.ecu_groups)
        for ecu in ecu_list:
            L().log(206, self._id_from_component(ecu))
            for setting in ecu.settings:
                val = self._get_setting_val(ecu, setting)                
                L().log(207, setting, val)
        
        # log all bus settings
        for buss in env.busses:
            bus = buss[0]
            L().log(206, self._id_from_component(bus))
            for setting in bus.settings:
                L().log(207, setting, val)
        L().log(205)

      
    def _lw_auth_connect_shared_vars(self, env, sec_module, ecu_list, ecu_specs):
        ''' 
        this method sets specific values defined in the security module to all AbstractECU objects connected
        to it. Thus it ensures that all settings are consistent if not explicitly defined otherwise.
        If the ECU got explicitly defined different settings, those settings will be used.
        Short:        
            if the ECU has a value dont set the sec mod for it
            if the ECU has no value use the same as the sec Module
        
        
            Input:  env:             AutomotiveEnvironmentSpec:           specification of the Environment
                    sec_module       SecLwAuthSecurityModule              security module that will be 
                    ecu_list         list                                 list of AbstractECUs
                    ecu_specs        list                                 list of AbstractECUSpecs
            Output: -  
        '''
        
        for ecu in ecu_list:
            try:  
                ecu_spec = self._ecu_spec_by_id(ecu.ecu_id, env.ecu_groups)                
                
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_sec_mod_cert_hashing_mech', sec_module, 'p_sec_mod_cert_hashing_mech')
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_sec_mod_cert_enc_mech', sec_module, 'p_sec_mod_cert_enc_mech')
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_sec_mod_cert_enc_mech_option', sec_module, 'p_sec_mod_cert_enc_mech_option')
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_sec_mod_cert_enc_keylen', sec_module, 'p_sec_mod_cert_enc_keylen')
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_sec_mod_cert_ca_len', sec_module, 'p_sec_mod_cert_ca_len')
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_sec_mod_cert_hash_size', sec_module, 'p_sec_mod_cert_hash_size')
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_sec_mod_cert_signed_hash_size', sec_module, 'p_sec_mod_cert_signed_hash_size') 

                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_ecu_auth_cert_hash_mech', sec_module, 'p_ecu_auth_cert_hash_mech') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_ecu_auth_cert_enc_mech', sec_module, 'p_ecu_auth_cert_enc_mech') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_ecu_auth_cert_enc_mech_option', sec_module, 'p_ecu_auth_cert_enc_mech_option') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_ecu_auth_cert_enc_keylen', sec_module, 'p_ecu_auth_cert_enc_keylen') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_ecu_auth_cert_ca_len', sec_module, 'p_ecu_auth_cert_ca_len') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_ecu_auth_cert_hash_unsigned_size', sec_module, 'p_ecu_auth_cert_hash_unsigned_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_ecu_auth_cert_hash_signed_size', sec_module, 'p_ecu_auth_cert_hash_signed_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_inner_cipher_size', sec_module, 'p_reg_msg_inner_cipher_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_outter_cipher_size', sec_module, 'p_reg_msg_outter_cipher_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_ecu_auth_conf_msg_size', sec_module, 'p_ecu_auth_conf_msg_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_req_msg_content_size', sec_module, 'p_req_msg_content_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_grant_msg_content_size', sec_module, 'p_grant_msg_content_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_outter_hash_size', sec_module, 'p_reg_msg_outter_hash_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_hash_alg', sec_module, 'p_reg_msg_hash_alg') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_inner_enc_method', sec_module, 'p_reg_msg_inner_enc_method') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_inner_enc_method_option', sec_module, 'p_reg_msg_inner_enc_method_option') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_inner_enc_keylen', sec_module, 'p_reg_msg_inner_enc_keylen') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_outter_enc_alg', sec_module, 'p_reg_msg_outter_enc_alg')  # PROBLEM: Falls das so aufgerufen priv und pubkeys beim laden inkonsistent
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_outter_enc_alg_option', sec_module, 'p_reg_msg_outter_enc_alg_option')  # PROBLEM: Falls das so aufgerufen priv und pubkeys beim laden inkonsistent
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_outter_enc_keylen', sec_module, 'p_reg_msg_outter_enc_keylen')  # LOADING MODE?
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_inner_cipher_size', sec_module, 'p_reg_msg_inner_cipher_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_outter_cipher_size', sec_module, 'p_reg_msg_outter_cipher_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_reg_msg_inner_content_size', sec_module, 'p_reg_msg_inner_content_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_grant_msg_content_size', sec_module, 'p_grant_msg_content_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_req_msg_cipher_size', sec_module, 'p_req_msg_cipher_size') 
                self._set_lw_ecu_connection(ecu_spec, ecu, 'p_req_msg_content_size', sec_module, 'p_req_msg_content_size') 
            except:    
                L().log_traceback()

    
    def _path_from_busses(self, env, start_component, dest_component, caller):  
        ''' finds the path from one component to the other recursively
            and returns it in shape of ['CAN_0', 'GW_1', 'CAN_1', 'GW_2', 'CAN_2']
                
            Input:  env:                   AutomotiveEnvironmentSpec:           specification of the Environment
                    start_component        AutomotiveComponent                  start component of path
                    dest_component         AutomotiveComponent                  destination component of path
                    caller                 AutomotiveComponent                  object calling this method (needed for recursive algorithm)
            Output: path                   list                                 path from start_component to dest_component in shape of ['CAN_0', 'GW_1', 'CAN_1', 'GW_2', 'CAN_2']
        '''
        
        # break condition
        if start_component == dest_component:
            return [start_component]
        
        # gateway: 
        if self._is_gateway(start_component):
            # search busses 
            for bus in start_component.connected_bus:                
                if bus == caller: continue
                val = self._path_from_busses(env, bus, dest_component, start_component)
                if val == None: continue
                return [start_component] + val
            
        # otherwise: 
        else:
            try:
                # search AbstractECUs 
                for ecu in start_component.connected_ecus:                     
                    if ecu == caller: continue
                    if not self._is_gateway(ecu): continue
                    val = self._path_from_busses(env, ecu, dest_component, start_component)
                    if val == None: continue
                    return [start_component] + val
                
            except: pass           
        return None

      
    def _register_ecus_to_sec_mod(self, env, ecu, ecu_specs):
        ''' if the given ecu is a security module then all 
            AbstractECUs that are defined in the AutomotiveEnvironmentSpec
            that are specified are connected to this Security Module 
                
            Input:  env:                   AutomotiveEnvironmentSpec:           specification of the Environment
                    ecu                    SecLwAuthSecurityModule              security module that gets specified ECUs connected
                    ecu_specs              AbstractECUSpecs                     specification of the security module
            Output: -                  
        '''
        try:
            # security module:
            if not self._is_sec_mod(ecu): return                   
            ecu_list = []
            
            # determine ECU groups
            for ky in env.sec_mod_ecu_register.keys():                
                ecu_groups = env.sec_mod_ecu_register[ky]
                for ecu_group in ecu_groups:
                    ecu_list += ecu_group                    
            
            # set shared variables     
            self._lw_auth_connect_shared_vars(env, ecu, ecu_list, ecu_specs)     
            
            # register ECU list to security module
            ecu.register_ecus(ecu_list)
        except:
            pass
    
      
    def _set_certification(self, env):
        ''' if a certification was defined this method 
            sets it during the building process
            
            Input:  env:                   AutomotiveEnvironmentSpec:           specification of the Environment
            Output: -     
        '''                           
        # Specified certification
        if env.apply_certification:
            self._apply_certification(env)
    
      
    def _set_jitter(self, ecu, ecu_specs):
        ''' if jitter was specified in the ecu_specs it is
            set here during the building process
            
            Input:  ecu:                 AbstractECU:           ecu object that will get jitter set
                    ecu_specs            AbstractECUSpec        ecu specification holding information about jitter value
            Output: - 
        
        '''
        try:
            if ecu_specs.apply_jitter:
                try: ecu.set_jitter(ecu_specs.apply_jitter)
                except: pass  # logging.error("Could not set jitter value to ECU %s" % ecu.__class__)
        except:
            pass
    
      
    def _set_lw_ecu_connection(self, ecu_specs, ecu, val_1, sec_module, val_2):
        ''' this method sets the setting val_1 of ECU ecu to the security modules settings value val_2 
            only if the ECU does not already have a value (defined in ecu_specs) for this setting specified
                
            Input:  ecu_specs            AbstractECUSpec            ecu specification holding information about jitter value
                    ecu:                 AbstractECU:               ecu object whose settings value is to be modified 
                    val_1                string                     Settings definition of the ecu e.g. 't_ecu_auth_trigger_intervall'
                    sec_module           SecLwAuthSecurityModule    security module object whose settings value is to be used for the ECU
                    val_2                string                     Settings definition of the security module e.g. 't_ecu_auth_trigger_intervall'
            Output: - 
        
        '''
        
        try:
            
            # ecu with valid value
            if val_1 in ecu_specs.timing_map_vals: 
                return
            
            # ecu has no valid value
            else:                                           
                fst = eval('ecu.settings["' + val_1 + '"]')
                scd = eval('sec_module.settings["' + val_2 + '"]')                
                ex_str = 'ecu.' + fst + '=' + 'sec_module.' + scd
            exec(ex_str)
            
        except:  
            L().log_traceback()
            L().log_err(200, val_1, val_2)
            
      
    def _set_setting(self, component, variable, value):
        ''' sets the value of a components setting from its 
            given variable
            e.g. 't_reg_msg_sym_keygen' is given as variable and a TLSECU 
                 object. Then the current value on which 't_reg_msg_sym_keygen' is
                 mapped on will be set
                 
            Input:  component:            AutomotiveComponent:               object under consideration
                    variable:             string:                            settings id to be evaluated
            Output: -
        '''
        
        val = component.settings[variable]
        execution_str = 'component.' + val + ' = value'
        exec(execution_str)   
                       
    
    def _set_startup_delay(self, ecu, ecu_specs):
        ''' this method sets the startup delay. When this delay is set
            this ECU is activated after the defined start time
        
            Input:    ecu            AbstractECU        ecu that gets the startupdelay
                      ecu_specs      AbstractECUSpec    ecu specs that has the information if a startup was specified
            Output:    -
        '''
        try:            
            ecu.set_startup_delay(ecu_specs.startup_delay)
        except:
            pass
                       
           
    def _verify_user_input_lwa(self, env):
        ''' checks the user input before the simulation starts
        
            Input:    env:                   AutomotiveEnvironmentSpec:           specification of the Environment
            Output:   -
        '''
        
        for ecu_group in env.ecu_groups:
            
            # extract     
            ecus = ecu_group[0]

            # check
            for ecu in ecus:         
                     
                if self._is_sec_mod(ecu):
                    self._verify_user_input_lwa_secmod(ecu)
                elif not self._is_gateway(ecu) and isinstance(ecu.ecuSW.comm_mod, SecureCommModule):
                    self._verify_user_input_lwa_ecu(ecu)                

    def _verify_user_input_lwa_secmod(self, ecu):
        ''' checks all values in the given AbstractECU for plausibility
                    
            Input:    ecu:                   SecLwAuthSecurityModule:           ECU to be checked
            Output:   -
            
        '''
        return
        dictio = {}
        
        # check if numeric
        dictio['t_ecu_auth_trigger_intervall'] = self._get_setting_val(ecu, 't_ecu_auth_trigger_intervall')        
        dictio['t_ecu_auth_trigger_process'] = self._get_setting_val(ecu, 't_ecu_auth_trigger_process')        
        dictio['p_sec_mod_cert_size'] = self._get_setting_val(ecu, 'p_sec_mod_cert_size')        
        dictio['p_reg_msg_inner_content_size'] = self._get_setting_val(ecu, 'p_reg_msg_inner_content_size')
        dictio['p_reg_msg_inner_cipher_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_reg_msg_inner_cipher_size'), self._get_setting_val(ecu, 'p_reg_msg_inner_content_size'), self._get_setting_val(ecu, 'p_reg_msg_inner_enc_method'), self._get_setting_val(ecu, 'p_reg_msg_inner_enc_keylen') , 'ENCRYPTION')
        dictio['t_ecu_auth_reg_msg_inner_dec'] = self._get_setting_val(ecu, 't_ecu_auth_reg_msg_inner_dec')
        dictio['t_ecu_auth_reg_msg_inner_dec'] = G().call_or_const(self._get_setting_val(ecu, 't_ecu_auth_reg_msg_inner_dec'), self._get_setting_val(ecu, 'p_reg_msg_inner_enc_method'), self._get_setting_val(ecu, 'p_reg_msg_inner_enc_keylen'), dictio['p_reg_msg_inner_cipher_size'], self._get_setting_val(ecu, 'p_reg_msg_inner_enc_method_option'))
        dictio['p_reg_msg_outter_hash_size'] = self._get_setting_val(ecu, 'p_reg_msg_outter_hash_size')
        dictio['p_reg_msg_inner_content_size'] = self._get_setting_val(ecu, 'p_reg_msg_inner_content_size')
        dictio['p_reg_msg_outter_cipher_size'] = self._get_setting_val(ecu, 'p_reg_msg_outter_cipher_size')
        dictio['t_ecu_auth_reg_msg_outter_dec'] = self._get_setting_val(ecu, 't_ecu_auth_reg_msg_outter_dec')
        hashed_size = G().call_or_const(self._get_setting_val(ecu, 'p_reg_msg_outter_hash_size'), self._get_setting_val(ecu, 'p_reg_msg_inner_content_size'), self._get_setting_val(ecu, 'p_reg_msg_hash_alg'), None, 'HASH')
        dictio['p_reg_msg_outter_hash_size'] = hashed_size
        cipher_size = G().call_or_const(self._get_setting_val(ecu, 'p_reg_msg_outter_cipher_size'), hashed_size, self._get_setting_val(ecu, 'p_reg_msg_outter_enc_alg'), self._get_setting_val(ecu, 'p_reg_msg_outter_enc_keylen'), 'SIGN')  
        dictio['p_reg_msg_outter_cipher_size'] = cipher_size
        time_val = G().call_or_const(self._get_setting_val(ecu, 't_ecu_auth_reg_msg_outter_dec'), self._get_setting_val(ecu, 'p_reg_msg_outter_enc_alg'), self._get_setting_val(ecu, 'p_reg_msg_outter_enc_keylen'), cipher_size, self._get_setting_val(ecu, 'p_reg_msg_outter_enc_alg_option'))
        dictio['t_ecu_auth_reg_msg_outter_dec'] = time_val
        dictio['t_ecu_auth_conf_msg_enc'] = self._get_setting_val(ecu, 't_ecu_auth_conf_msg_enc')
        dictio['p_ecu_auth_conf_msg_size'] = self._get_setting_val(ecu, 'p_ecu_auth_conf_msg_size') 
        dictio['p_sec_mod_conf_msg_sending_size'] = self._get_setting_val(ecu, 'p_sec_mod_conf_msg_sending_size')
        dictio['p_ecu_auth_conf_msg_size'] = self._get_setting_val(ecu, 'p_ecu_auth_conf_msg_size')
        dictio['p_sec_mod_conf_msg_sending_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_sec_mod_conf_msg_sending_size'), self._get_setting_val(ecu, 'p_ecu_auth_conf_msg_size'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, 'ENCRYPTION')
        dictio['p_ecu_auth_cert_hash_signed_size'] = self._get_setting_val(ecu, 'p_ecu_auth_cert_hash_signed_size')
        dictio['p_ecu_auth_cert_hash_unsigned_size'] = self._get_setting_val(ecu, 'p_ecu_auth_cert_hash_unsigned_size')
        dictio['p_ecu_auth_cert_hash_signed_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_ecu_auth_cert_hash_signed_size'), self._get_setting_val(ecu, 'p_ecu_auth_cert_hash_unsigned_size'), self._get_setting_val(ecu, 'p_ecu_auth_cert_enc_mech'), self._get_setting_val(ecu, 'p_ecu_auth_cert_enc_keylen'), 'SIGN')
        dictio['t_ecu_auth_reg_msg_validate_cert'] = self._get_setting_val(ecu, 't_ecu_auth_reg_msg_validate_cert')
        t_valid_cert = G().call_or_const(self._get_setting_val(ecu, 't_ecu_auth_reg_msg_validate_cert'), self._get_setting_val(ecu, 'p_ecu_auth_cert_hash_mech'), self._get_setting_val(ecu, 'p_ecu_auth_cert_enc_mech'), self._get_setting_val(ecu, 'p_ecu_auth_cert_enc_keylen'), self._get_setting_val(ecu, 'p_ecu_auth_cert_ca_len'), self._get_setting_val(ecu, 'p_ecu_auth_cert_hash_unsigned_size'), dictio['p_ecu_auth_cert_hash_signed_size'], self._get_setting_val(ecu, 'p_ecu_auth_cert_enc_mech_option'))
        t_cmp_hash = G().call_or_const(self._get_setting_val(ecu, 't_ecu_auth_reg_msg_create_comp_hash'), self._get_setting_val(ecu, 'p_reg_msg_inner_content_size'), self._get_setting_val(ecu, 'p_reg_msg_hash_alg'))
        t_hash_reg = self._get_setting_val(ecu, 't_ecu_auth_reg_msg_comp_hash_process')
        dictio['t_ecu_auth_reg_msg_validate_cert'] = t_valid_cert
        dictio['t_ecu_auth_reg_msg_create_comp_hash'] = self._get_setting_val(ecu, 't_ecu_auth_reg_msg_create_comp_hash')
        dictio['t_ecu_auth_reg_msg_create_comp_hash'] = t_cmp_hash
        dictio['t_ecu_auth_reg_msg_comp_hash_process'] = t_hash_reg
        dictio['t_str_auth_keygen_grant_msg'] = G().call_or_const(self._get_setting_val(ecu, 't_str_auth_keygen_grant_msg'), self._get_setting_val(ecu, 'p_str_auth_ses_key_enc_alg'), self._get_setting_val(ecu, 'p_str_auth_ses_key_enc_keylen'))             
        dictio['t_str_auth_enc_grant_msg'] = G().call_or_const(self._get_setting_val(ecu, 't_str_auth_enc_grant_msg'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, self._get_setting_val(ecu, 'p_grant_msg_content_size'), SymAuthMechEnum.CCM)
        dictio['t_str_auth_keygen_grant_msg'] = self._get_setting_val(ecu, 't_str_auth_keygen_grant_msg')
        dictio['t_str_auth_enc_grant_msg'] = self._get_setting_val(ecu, 't_str_auth_enc_grant_msg')
        dictio['p_grant_msg_content_size'] = self._get_setting_val(ecu, 'p_grant_msg_content_size')
        dictio['p_str_auth_grant_msg_sending_size'] = self._get_setting_val(ecu, 'p_str_auth_grant_msg_sending_size')
        dictio['p_grant_msg_content_size'] = self._get_setting_val(ecu, 'p_grant_msg_content_size')
        sending_size = G().call_or_const(self._get_setting_val(ecu, 'p_str_auth_grant_msg_sending_size'), self._get_setting_val(ecu, 'p_grant_msg_content_size'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, 'ENCRYPTION')                          
        dictio['p_str_auth_grant_msg_sending_size'] = sending_size
        cipher_size = G().call_or_const(self._get_setting_val(ecu, 'p_req_msg_cipher_size'), self._get_setting_val(ecu, 'p_req_msg_content_size'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, 'ENCRYPTION')  
        dictio['p_req_msg_cipher_size'] = cipher_size
        cipher_size = G().call_or_const(self._get_setting_val(ecu, 'p_req_msg_cipher_size'), self._get_setting_val(ecu, 'p_req_msg_content_size'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, 'ENCRYPTION')  
        decr_time = G().call_or_const(self._get_setting_val(ecu, 't_str_auth_decr_req_msg'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, cipher_size, SymAuthMechEnum.CBC)
        dictio['t_str_auth_decr_req_msg'] = decr_time
        dictio['t_str_auth_decr_req_msg'] = self._get_setting_val(ecu, 't_str_auth_decr_req_msg')
        dictio['t_str_auth_enc_deny_msg'] = self._get_setting_val(ecu, 't_str_auth_enc_deny_msg')
        dictio['p_grant_msg_content_size'] = self._get_setting_val(ecu, 'p_grant_msg_content_size')
        dictio['p_str_auth_deny_msg_sending_size'] = self._get_setting_val(ecu, 'p_str_auth_deny_msg_sending_size')
        time_val = G().call_or_const(self._get_setting_val(ecu, 'p_grant_msg_content_size'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, self._get_setting_val(ecu, 'p_grant_msg_content_size'), SymAuthMechEnum.CBC)
        sending_size = G().call_or_const(self._get_setting_val(ecu, 'p_str_auth_deny_msg_sending_size'), self._get_setting_val(ecu, 'p_grant_msg_content_size'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, 'ENCRYPTION')  
        dictio['p_grant_msg_content_size'] = time_val
        dictio['p_str_auth_deny_msg_sending_size'] = sending_size
        
        any_error = False
        for k in dictio:
            if not isinstance(dictio[k], (int, float, complex)):
                if hasattr(dictio[k], '__call__'): continue
                try: logging.error("ECU %s: Component %s should be numeric but is of type %s" % (ecu.ecu_id, k , dictio[k].__class__))
                except: logging.error("ECU %s: Component %s should be numeric but is %s" % (ecu.ecu_id, k , dictio[k]))
                any_error = True
        if any_error: sys.exit(0)
        
        # check if algorithm
        dictio = {}
        # dictio['p_reg_msg_outter_enc_alg_option'] = self._get_setting_val(ecu, 'p_reg_msg_outter_enc_alg_option')
        # dictio['p_reg_msg_inner_enc_method_option'] = self._get_setting_val(ecu, 'p_reg_msg_inner_enc_method_option')
        dictio['p_reg_msg_inner_enc_method'] = self._get_setting_val(ecu, 'p_reg_msg_inner_enc_method')        
        dictio['p_reg_msg_outter_enc_alg'] = self._get_setting_val(ecu, 'p_reg_msg_outter_enc_alg')
        dictio['p_ecu_auth_cert_enc_mech'] = self._get_setting_val(ecu, 'p_ecu_auth_cert_enc_mech')
        dictio['p_str_auth_ses_key_enc_alg'] = self._get_setting_val(ecu, 'p_str_auth_ses_key_enc_alg')
        
        any_error = False
        for k in dictio:
            if not isinstance(dictio[k], (AsymAuthMechEnum, SymAuthMechEnum)):          
                try: logging.error("ECU %s: Component %s should be AsymAuthEnum/SymAuthMechEnum but is of type %s" % (ecu.ecu_id, k , dictio[k].__class__))
                except: logging.error("ECU %s: Component %s should be AsymAuthEnum/SymAuthMechEnum but is %s" % (ecu.ecu_id, k , dictio[k]))
                any_error = True
        if any_error: sys.exit(0)
        
        
        # hash algorithm
        dictio = {}
        dictio['p_reg_msg_hash_alg'] = self._get_setting_val(ecu, 'p_reg_msg_hash_alg')
        any_error = False
        for k in dictio:
            if not isinstance(dictio[k], (HashMechEnum)):          
                try: logging.error("ECU %s: Component %s should be HashMechEnum but is of type %s" % (ecu.ecu_id, k , dictio[k].__class__))
                except: logging.error("ECU %s: Component %s should be HashMechEnum but is %s" % (ecu.ecu_id, k , dictio[k]))
                any_error = True
        if any_error: sys.exit(0)
        
        # check if key length
        dictio = {}
        dictio['p_reg_msg_inner_enc_keylen'] = self._get_setting_val(ecu, 'p_reg_msg_inner_enc_keylen')        
        dictio['p_reg_msg_inner_enc_keylen'] = self._get_setting_val(ecu, 'p_reg_msg_inner_enc_keylen')
        dictio['p_reg_msg_outter_enc_keylen'] = self._get_setting_val(ecu, 'p_reg_msg_outter_enc_keylen')
        dictio['p_reg_msg_outter_enc_keylen'] = self._get_setting_val(ecu, 'p_reg_msg_outter_enc_keylen')
        dictio['p_ecu_auth_cert_enc_keylen'] = self._get_setting_val(ecu, 'p_ecu_auth_cert_enc_keylen')
        dictio['p_str_auth_ses_key_enc_keylen'] = self._get_setting_val(ecu, 'p_str_auth_ses_key_enc_keylen')
        
        any_error = False
        for k in dictio:
            if not isinstance(dictio[k], (AuKeyLengthEnum)):          
                try: logging.error("ECU %s: Component %s should be AuKeyLengthEnum but is of type %s" % (ecu.ecu_id, k , dictio[k].__class__))
                except: logging.error("ECU %s: Component %s should be AuKeyLengthEnum but is %s" % (ecu.ecu_id, k , dictio[k]))
                any_error = True
        if any_error: sys.exit(0)

    def _verify_user_input_lwa_ecu(self, ecu):
        ''' checks all values in the given AbstractECU for plausibility
                    
            Input:    ecu:                   AbstractECU:           ECU to be checked
            Output:   -            
        '''
        return
        dictio = {}
        
        dictio['t_normal_msg_dec'] = G().call_or_const(self._get_setting_val(ecu, 't_normal_msg_dec'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, 10, SymAuthMechEnum.CBC)
        dictio['t_normal_msg_enc'] = G().call_or_const(self._get_setting_val(ecu, 't_normal_msg_enc'), SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, 10, SymAuthMechEnum.CBC)
        dictio['t_req_msg_stream_enc'] = G().call_or_const(self._get_setting_val(ecu, 't_req_msg_stream_enc'), self._get_setting_val(ecu, 'p_req_msg_content_size'), self._get_setting_val(ecu, 'p_ecu_sym_key_alg'), \
                                                         self._get_setting_val(ecu, 'p_ecu_sym_key_keylen'), self._get_setting_val(ecu, 'p_ecu_sym_key_alg_mode'))        
        dictio['p_req_msg_content_size'] = self._get_setting_val(ecu, 'p_req_msg_content_size')
        dictio['enc_len'] = EncryptionSize().output_size(10, SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, 'ENCRYPTION')  
        dictio['p_grant_msg_cipher_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_grant_msg_cipher_size'), self._get_setting_val(ecu, 'p_grant_msg_content_size'), \
                                         SymAuthMechEnum.AES, AuKeyLengthEnum.bit_128, 'ENCRYPTION')         
        dictio['p_grant_msg_content_size'] = self._get_setting_val(ecu, 'p_grant_msg_content_size')
        dictio['p_req_msg_content_size'] = self._get_setting_val(ecu, 'p_req_msg_content_size')
        dictio['p_req_msg_sending_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_req_msg_sending_size'), self._get_setting_val(ecu, 'p_req_msg_content_size'), \
                                                          self._get_setting_val(ecu, 'p_ecu_sym_key_alg'), self._get_setting_val(ecu, 'p_ecu_sym_key_keylen'), 'ENCRYPTION')           
        dictio['p_grant_msg_cipher_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_grant_msg_cipher_size'), self._get_setting_val(ecu, 'p_grant_msg_content_size'), \
                                                           self._get_setting_val(ecu, 'p_ecu_sym_key_alg'), self._get_setting_val(ecu, 'p_ecu_sym_key_keylen'), 'ENCRYPTION') 
        dictio['t_grant_msg_stream_dec'] = G().call_or_const(self._get_setting_val(ecu, 't_grant_msg_stream_dec'), self._get_setting_val(ecu, 'p_ecu_sym_key_alg'), self._get_setting_val(ecu, 'p_ecu_sym_key_keylen'), dictio['p_grant_msg_cipher_size'] , self._get_setting_val(ecu, 'p_ecu_sym_key_alg_mode'))        
        dictio['t_deny_msg_stream_dec'] = G().call_or_const(self._get_setting_val(ecu, 't_deny_msg_stream_dec'), self._get_setting_val(ecu, 'p_ecu_sym_key_alg'), self._get_setting_val(ecu, 'p_ecu_sym_key_keylen'), dictio['p_grant_msg_cipher_size'], self._get_setting_val(ecu, 'p_ecu_sym_key_alg_mode'))
        dictio['t_reg_msg_sym_keygen'] = G().call_or_const(self._get_setting_val(ecu, 't_reg_msg_sym_keygen'), self._get_setting_val(ecu, 'p_ecu_sym_key_alg'), self._get_setting_val(ecu, 'p_ecu_sym_key_keylen'))
        dictio['p_reg_msg_inner_content_size'] = self._get_setting_val(ecu, 'p_reg_msg_inner_content_size')
        dictio['p_grant_msg_cipher_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_grant_msg_cipher_size'), self._get_setting_val(ecu, 'p_grant_msg_content_size'), self._get_setting_val(ecu, 'p_ecu_sym_key_alg'), self._get_setting_val(ecu, 'p_ecu_sym_key_keylen'), 'ENCRYPTION') 
        dictio['t_reg_msg_inner_enc'] = G().call_or_const(self._get_setting_val(ecu, 't_reg_msg_inner_enc'), self._get_setting_val(ecu, 'p_reg_msg_inner_content_size'), self._get_setting_val(ecu, 'p_reg_msg_inner_enc_method'), self._get_setting_val(ecu, 'p_reg_msg_inner_enc_keylen'), self._get_setting_val(ecu, 'p_reg_msg_inner_enc_method_option'))
        dictio['t_reg_msg_hash'] = G().call_or_const(self._get_setting_val(ecu, 't_reg_msg_hash'), self._get_setting_val(ecu, 'p_reg_msg_inner_content_size'), self._get_setting_val(ecu, 'p_reg_msg_hash_alg'))
        dictio['p_reg_msg_inner_content_size'] = self._get_setting_val(ecu, 'p_reg_msg_inner_content_size')
        dictio['p_reg_msg_outter_hash_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_reg_msg_outter_hash_size'), self._get_setting_val(ecu, 'p_reg_msg_inner_content_size'), self._get_setting_val(ecu, 'p_reg_msg_hash_alg'), None, 'HASH')
        dictio['t_reg_msg_outter_enc'] = G().call_or_const(self._get_setting_val(ecu, 't_reg_msg_outter_enc'), dictio['p_reg_msg_outter_hash_size'], self._get_setting_val(ecu, 'p_reg_msg_outter_enc_alg'), self._get_setting_val(ecu, 'p_reg_msg_outter_enc_keylen'), self._get_setting_val(ecu, 'p_reg_msg_outter_enc_alg_option')) 
        dictio['p_reg_msg_outter_cipher_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_reg_msg_outter_cipher_size'), dictio['p_reg_msg_outter_hash_size'], self._get_setting_val(ecu, 'p_reg_msg_outter_enc_alg'), self._get_setting_val(ecu, 'p_reg_msg_outter_enc_keylen'), 'SIGN')
        dictio['p_ecu_cert_sending_size'] = self._get_setting_val(ecu, 'p_ecu_cert_sending_size')
        dictio['p_sec_mod_cert_hash_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_sec_mod_cert_hash_size'), dictio['p_ecu_cert_sending_size'], self._get_setting_val(ecu, 'p_sec_mod_cert_hashing_mech'), None, 'HASH')
        dictio['p_sec_mod_cert_ca_len'] = self._get_setting_val(ecu, 'p_sec_mod_cert_ca_len')
        dictio['p_sec_mod_cert_signed_hash_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_sec_mod_cert_signed_hash_size'), dictio['p_sec_mod_cert_hash_size'], self._get_setting_val(ecu, 'p_sec_mod_cert_enc_mech'), self._get_setting_val(ecu, 'p_sec_mod_cert_enc_keylen'), 'SIGN')
        dictio['t_adv_msg_secmodcert_enc'] = G().call_or_const(self._get_setting_val(ecu, 't_adv_msg_secmodcert_enc'), self._get_setting_val(ecu, 'p_sec_mod_cert_hashing_mech'), self._get_setting_val(ecu, 'p_sec_mod_cert_enc_mech'), \
                                            self._get_setting_val(ecu, 'p_sec_mod_cert_enc_keylen'), self._get_setting_val(ecu, 'p_sec_mod_cert_ca_len'), \
                                            dictio['p_sec_mod_cert_signed_hash_size'], dictio['p_sec_mod_cert_hash_size'], self._get_setting_val(ecu, 'p_sec_mod_cert_enc_mech_option'))
        dictio['p_conf_msg_cipher_size'] = G().call_or_const(self._get_setting_val(ecu, 'p_conf_msg_cipher_size'), self._get_setting_val(ecu, 'p_ecu_auth_conf_msg_size'), \
                                                           self._get_setting_val(ecu, 'p_ecu_sym_key_alg'), self._get_setting_val(ecu, 'p_ecu_sym_key_keylen'), 'ENCRYPTION')
        dictio['t_conf_msg_dec_time'] = G().call_or_const(self._get_setting_val(ecu, 't_conf_msg_dec_time'), self._get_setting_val(ecu, 'p_ecu_sym_key_alg'), self._get_setting_val(ecu, 'p_ecu_sym_key_keylen'), dictio['p_conf_msg_cipher_size'] , self._get_setting_val(ecu, 'p_ecu_sym_key_alg_mode'))
        
        any_error = False
        for k in dictio:
            if not isinstance(dictio[k], (int, float, complex)):
                if hasattr(dictio[k], '__call__'): continue
                try: logging.error("ECU %s: Component %s should be numeric but is of type %s" % (ecu.ecu_id, k , dictio[k].__class__))
                except: logging.error("ECU %s: Component %s should be numeric but is %s" % (ecu.ecu_id, k , dictio[k]))
                any_error = True
        if any_error: sys.exit(0)
        

        dictio = {}
        # dictio['p_sec_mod_cert_enc_mech_option'] = self._get_setting_val(ecu, 'p_sec_mod_cert_enc_mech_option')
        # dictio['p_reg_msg_inner_enc_method_option'] = self._get_setting_val(ecu, 'p_reg_msg_inner_enc_method_option')   
        dictio['p_ecu_sym_key_alg'] = self._get_setting_val(ecu, 'p_ecu_sym_key_alg')
        dictio['p_reg_msg_inner_enc_method'] = self._get_setting_val(ecu, 'p_reg_msg_inner_enc_method')           
        dictio['p_sec_mod_cert_enc_mech'] = self._get_setting_val(ecu, 'p_sec_mod_cert_enc_mech')        
        dictio['p_ecu_sym_key_alg_mode'] = self._get_setting_val(ecu, 'p_ecu_sym_key_alg_mode')
        any_error = False
        for k in dictio:
            if not isinstance(dictio[k], (AsymAuthMechEnum, SymAuthMechEnum)):          
                try: logging.error("ECU %s: Component %s should be AsymAuthEnum/SymAuthMechEnum but is of type %s" % (ecu.ecu_id, k , dictio[k].__class__))
                except: logging.error("ECU %s: Component %s should be AsymAuthEnum/SymAuthMechEnum but is %s" % (ecu.ecu_id, k , dictio[k]))
                any_error = True
        if any_error: sys.exit(0)
        
        
        dictio = {}
        dictio['p_ecu_sym_key_keylen'] = self._get_setting_val(ecu, 'p_ecu_sym_key_keylen')
        dictio['p_reg_msg_inner_enc_keylen'] = self._get_setting_val(ecu, 'p_reg_msg_inner_enc_keylen')
        dictio['p_sec_mod_cert_enc_keylen'] = self._get_setting_val(ecu, 'p_sec_mod_cert_enc_keylen')
        any_error = False
        for k in dictio:
            if not isinstance(dictio[k], (AuKeyLengthEnum)):          
                try: logging.error("ECU %s: Component %s should be AuKeyLengthEnum but is of type %s" % (ecu.ecu_id, k , dictio[k].__class__))
                except: logging.error("ECU %s: Component %s should be AuKeyLengthEnum but is %s" % (ecu.ecu_id, k , dictio[k]))
                any_error = True
        if any_error: sys.exit(0)
        

        dictio = {}
        dictio['p_sec_mod_cert_hashing_mech'] = self._get_setting_val(ecu, 'p_sec_mod_cert_hashing_mech')
        any_error = False
        for k in dictio:
            if not isinstance(dictio[k], (HashMechEnum)):          
                try: logging.error("ECU %s: Component %s should be HashMechEnum but is of type %s" % (ecu.ecu_id, k , dictio[k].__class__))
                except: logging.error("ECU %s: Component %s should be HashMechEnum but is %s" % (ecu.ecu_id, k , dictio[k]))
                any_error = True
        if any_error: sys.exit(0)
        

class TimingFunctionSet(object):
    '''
    this class contains the association between timing varibales
    and functions to be called on those variables
    '''
    
      
    def __init__(self):
        self.timing_map = {}  # self.timing_map['ECU_0']['t_my_timing'] = myFunction       
      
            
    def set_mapping(self, comp_id, time_id, new_func):
        ''' This method sets the interpreter function for
            the timing with id time_id to new_func 
            
            e.g. def my_func(args*):
                    # do something to determine the time from the passed parameters
                    time_value = 0.00012
                    return time_value    
             
                time_id = 't_my_test', comp_id = 'ECU_0' new_func = my_func
                -> then the method my_func will be called every time the variable associated
                   to 't_my_test' is accessed            
            
            Input:    comp_id:                   string            ECU to be modified
                      time_id                    string            settings id of the timing value that will get a new function
                      new_func                   method            new method that will be used for this timing variable
            Output:   -
        '''
            
        try:
            self.timing_map[comp_id]
        except:
            self.timing_map[comp_id] = {}
        try:
            self.timing_map[comp_id][time_id]
        except:
            self.timing_map[comp_id][time_id] = {}            
        self.timing_map[comp_id][time_id] = new_func

      
    def set_mapping_from_function_set(self, comp_id, time_func_class):
        ''' this method takes a AbstractTimingFunctions Object and 
            sets all of its functions to the object with id comp_id
            
            Input:    comp_id:                   string            ECU whose settings will be modified
                      time_func_class            FunctionSet       Set of functions that defines multiple associations of functions to timing variables
            Output:   -
        '''
        
        self.timing_map[comp_id] = time_func_class.get_function_map()
        
class StoppableThread(threading.Thread):
    '''
    this class starts a Thread with a tkinter Button that can 
    be used to stop the thread without destroying the GUI and
    the main process
    '''
    
    def __init__(self, env, name='StoppableThread'):
        ''' 
            constructor, setting initial variables 
        
            Input:  env:    simpy.Environment        simpy Environment that will be surveilanced 
            Output: - 
        '''
        self._stopevent = threading.Event()
        self._sleepperiod = 1.0
        threading.Thread.__init__(self, name=name)
        self.env = env
        self.button_end = False
  
    def onKeyPress(self): 
        '''
            stops the thread once the key is pressed
            
            Input:  -
            Output: - 
        '''
        # logging.info("Forced to stop simulation")
        self.button_end = True
        self.env.schedule(None, URGENT, 0)
        self.root.destroy()
  
    def run(self):      
        '''
            opens a start button and runs the tkinter thread in a
            loop
            
            Input:  -
            Output: - 
        '''
        # create GUI
        self.root = tkinter.Tk()
        self.root.geometry('130x35')
        self.root.resizable(width=False, height=False)
        but = tkinter.Button(self.root, text="Stop Simulation", command=self.onKeyPress)
        but.place(x=10, y=5)        
        font = Font(family='Helvetica', size=10, weight='bold') 
        but['font'] = font        
        self.root.mainloop()
 
        # main control loop
        count = 0
        while not self._stopevent.isSet():
            count += 1
            self._stopevent.wait(self._sleepperiod)
        print("Stopbutton Thread finalized")
        
    def join(self, timeout=None):
        ''' 
            Stop the thread and wait for it to end. 
            
            Input:  -
            Output: - 
        '''
        self._stopevent.set()
        threading.Thread.join(self, timeout)
