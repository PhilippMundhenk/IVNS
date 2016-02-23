'''
Created on 25 Apr, 2015

This module is the main interface to be accessed by any Participant who is
willing to use the simulation. It is meant to hide the complexity behind the
implementation providing a simple to use possibility to access the simulation.
E.g. the GUI will use this API to generate its simulation, as well as to access
it and receive information from it

@author: artur.mrowca
'''
import logging
from api.core.api_core import APICore
from components.security.certification.certification_authority import CAHierarchy
from tools.ecu_logging import ECULogger
import os

def autoset_gateway_filters(env, sec_id):
    ''' depending on the allowed streams this method
        sets a filter to each gateway, so that only 
        allowed streams defined in the ecu with sec_id 
        are forwarded
        Input:  env:                   AutomotiveEnvironmentSpec:  specification of the Environment
                sec_id:                string:                     Id of security module
        Output: -
    '''
    APICore().autoset_gateway_filters(env, sec_id)
     
def register_ecu_classes(class_path):
    ''' all AbstractECU classes that are present in the folder
        class_path will be createable within the environment
            
        Input:  class_path:      string
        Output: -    
    '''
    APICore().register_ecu_classes(class_path)
        
def register_bus_classes(class_path):
    ''' all AbstractBus classes that are present in the folder
        class_path will be createable within the environment
            
        Input:  class_path:      string
        Output: -     
    '''
    APICore().register_bus_classes(class_path)

def create_environment(app_lifetime):
    ''' create the automotive environment specification
        that is used to generate a valid environment
        
        Input:  app_lifetime:       float
        Output: -        
    '''
    return APICore().create_environment(app_lifetime)

def gateway_filter_bus(gateway_group, can_dict):
    ''' Sets a fixed filter to the gateway. The can_dict contains
        CAN IDs as keys and a list of allowed message ids as values. 
        Thus all allowed messages will be forwarded and the remaining once
        will be blocked
        e.g. api.gateway_filter_bus(gateway_group_1, {'CAN_0':[2,3,4], 'CAN_1':[5,6,7]})  
             this filter would act as follows. If a message with either 2,3,4 arrives
             through CAN_0 to the gateway it will be forwarded. Any other message arriving
             on that bus will be discarded. Analogously messages 5,6,7 arriving over CAN_1
             will be forwarded and others not
        Input:  gateway_group:   list of Gateway objects
                can_dict:        dictionary: key: can id value: list of message ids
        Output: -   
    '''
    APICore().gateway_filter_bus(gateway_group, can_dict)
    
def gateway_filter_sending_bus(gateway_group, can_dict):
    ''' Sets a fixed filter to the gateway. The can_dict contains
        CAN IDs as keys and a list of allowed message ids as values. 
        Thus all allowed messages will be forwarded and the remaining once
        will be blocked
        e.g. api.gateway_filter_sending_bus(gateway_group_1, {'CAN_0':[2,3,4], 'CAN_1':[2, 5,6,7]})  
             this filter would act as follows. If a message with either 2 arrives
             on any port of the gateway it will be forwarded to CAN_0 and CAN_1. If 3,4 arrives on 
             any port it will be forwarded to CAN_0 only. etc 
        Input:  gateway_group:   list of Gateway objects
                can_dict:        dictionary: key: can id value: list of message ids
        Output: -   
        '''
    APICore().gateway_filter_sending_bus(gateway_group, can_dict)

def set_app_lifetime(self, myEnv, app_lifetime):
    ''' sets the lifetime of the application
            Input:  env:           AutomotiveEnvironmentSpec
            Output: - 
    '''
    APICore().set_app_lifetime(myEnv, app_lifetime)

def set_busses(env, nr_elements, bus_type_id, bus_spec):
    ''' given the bus_type that has to be generated and the bus_spec
        object that is necessary to create the object this method sets
        number nr_elements Busses of that type into the environment
            
        Input:  env:                AutomotiveEnvironmentSpec
                nr_elements:        int
                bus_type_id:        string
                bus_spec:           BusSpec (depending on the generated bus)
        
        Output: list of AbstractBus Objects
    
    '''
    
    return APICore().set_busses(env, nr_elements, bus_type_id, bus_spec)

def set_ecus(env, nr_elements, ecu_type_id, ecu_spec):
    ''' adds a certain number of ecus of a certain type with settings 
        defined in ecu_spec to the environment. 
        
        Input:  env:                 AutomotiveEnvironmentSpec:         specification of the Environment
                nr_elements:         int                                number of ECUs to be added
                ecu_type_id          string                             class name of the AbstractECU to be created as string
                ecu_spec             AbstractECUSpec                    AbstractECUSpec that specifies the settings for this group of ECUs
        Output: ecu_group            List of AbstractECU objects        instances of created ECUs
    '''
    return APICore().set_ecus(env, nr_elements, ecu_type_id, ecu_spec)    

def connect_bus_by_id(env, bus_id, lst_add_ids):
    ''' 
        adds all ECUs with ids in lst_add_ids to
        the elements that will be connected to the 
        Bus with Bus ID bus_id    
        
        Input:  env:               AutomotiveEnvironmentSpec:          specification of the Environment
                bus_id:            string:                             id of the bus to be connected
                lst_add_ids:       list of strings                     list of ids of AbstractECU instances that will be connected to the bus
        Output: -
    '''  
    APICore().connect_bus(env, bus_id, lst_add_ids)    

def connect_bus_by_obj(env, bus_id, lst_add_obj):
    ''' 
        adds all ECU objects in lst_add_obj to
        the elements that will be connected to the 
        Bus with Bus ID bus_id    
        
        Input:  env:               AutomotiveEnvironmentSpec:         specification of the Environment
                bus_id:            string                             id of the bus to be connected
                new_obj_list:      list of AbstractECU objects        list of AbstractECU objects
        Output: -
    '''   
    APICore().connect_bus_obj(env, bus_id, lst_add_obj)    

def build_simulation(env):
    ''' 
        all specification that has been passed to the
        AutomotiveEnvironmentSpec object env will be build 
        in this stage
        
        Input:  env:                 AutomotiveEnvironmentSpec:     specification of the Environment
        Output: -
    '''    
    APICore().build_sim_param(env)

def open_simulation_stop_button(env):
    ''' starts a seperate thread that opens a stop button that 
        can be used to interrupt the simulation without closing the GUI
        and finishing the automotive Environment and simpy Process
        
        Input:    env:            AutomotiveEnvironmentSpec: specification of the Environment
        Output:     -
            '''
    APICore().open_simulation_stop_button(env)

def run_simulation(env):
    ''' this method starts the actual environment by first creating a 
        simulation parameter and then starting the environment from 
        that created parameter

        Input:  env:           AutomotiveEnvironmentSpec:     specification of the Environment
        Output: - 
    '''
    return APICore().run_simulation(env)

def show_logging(lev, file_path, show_output):
    ''' shows the logging and saves it to the given
        file '''
    ECULogger().enabled = True
    if show_output:
        logging.getLogger().setLevel(lev)   
        if not os.path.exists(os.path.dirname(file_path)):
            os.mkdir(os.path.dirname(file_path))  
        if not os.path.exists(file_path):
            open(file_path, 'a').close()
        handler = logging.FileHandler(filename=file_path, mode='w')    
        logging.getLogger().addHandler(handler)
    ECULogger().show_outputf(show_output)
    
def console_logging(lev, show_output):
    ''' shows the logging only in the console '''
    ECULogger().enabled = True
    if show_output:
        logging.getLogger().setLevel(lev)
    ECULogger().show_outputf(show_output)
    
'''===============================================================================
     Lightweight Authentication 
==============================================================================='''

def register_ecu_groups_to_secmod(env, sec_mod_id, ecu_groups):
    ''' in order for the security module to know about the ecus existence
        it is necessary to connect the ECU to the security module 
        
        Input:  env:               AutomotiveEnvironmentSpec:            specification of the Environment
                sec_mod_id:        string                                id of the security module
                ecu_groups:        list                                  list of ecu object lists: [[ecu_obj_1, ecu_obj_2, ...], [ecu_obj_12, ecu_obj_13, ...], ...]
        
        Output: -
    '''
    APICore().register_ecu_groups_to_secmod(env, sec_mod_id, ecu_groups)

'''===============================================================================
        Certification
==============================================================================='''

def create_cert_manager(ca_hierarchy=CAHierarchy()):
    ''' 
        creates a certificate manager object from 
        a CAHierarchy object 
        
        Input:  ca_hierarchy:                  CAHierarchy:            Hierarchy of Certification Authorities
        Output: cert_manage                    CertificateManager      entity that holds the certificates for all parties
    '''  
    return APICore().cert_manager(ca_hierarchy)

def ecu_list_from_groups(ecu_groups):
    ''' returns all AbstractECU objects that are specified in the 
        ecu_groups as list
    
        Input:  ecu_groups:         list                [ ecu_group_1, ecu_group_2,...]  with ecu_group_i = [ecu_list_1, ecu_list_2,...], 
                                                                                        with ecu_list_i = [abstract_ecu_1, abstract_ecu_2,...]     
        Output: ecu_list            list                list of AbstractECUs
    '''    
    return APICore().ecu_list_from_groups(ecu_groups)

def generate_valid_ecu_cert_cfg(cert_mgr, ecu_id, ca_id, sec_mod_id, valid_from, valid_till):
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
    return APICore().generate_valid_ecu_cert_cfg(cert_mgr, ecu_id, ca_id, sec_mod_id, valid_from, valid_till)

def generate_valid_sec_mod_cert_cfg(cert_mgr, sec_mod_id, ca_id, ecu_id_list, valid_from, valid_till):
    '''all ECUs that are given in the ecu_id_list will get a valid list of root certificates
        to be able to verify the Security modules authenticity
        
        Input:  cert_manager:      CertificateManager        entity that holds the certificates for all parties
                ca_id:             string/CAEnum             Id of the Certification Authority that authorizes this certificate
                sec_mod_id:        string                    id of the security module
                ecu_id_list:       list of string            list of ecu ids 
                valid_from:        number                    certificate validity start time
                valid_till:        number                    certificate validity end time
        Output: -        
    '''
    return APICore().generate_valid_sec_mod_cert_cfg(cert_mgr, ca_id, sec_mod_id, ecu_id_list, valid_from, valid_till)

def apply_certification(env, cert_mgr):
    ''' applies the certification specified in the 
        certificate manager object to the environment 
        
        Input:  env:                 AutomotiveEnvironmentSpec:     specification of the Environment
                cert_manager:        CertificateManager:            entity that holds the certificates for all parties
        Output: -
        '''
    APICore().apply_certification(env, cert_mgr)

def add_allowed_stream(env, sec_mod_id, new_stream):
    ''' adds defined streams to the environment
        1. sets sterams in security module
        2. sets hw filter with allowed streams in each ecu transceiver
    
        Input:  env:                 AutomotiveEnvironmentSpec:     specification of the Environment
                sec_mod_id:          string:                        id of security module
                new_stream:          MessageStream                  Stream that is allowed in this environment
        Output: -
    '''
    APICore().add_allowed_stream(env, sec_mod_id, new_stream)
    
def set_stream(env, new_stream):
    ''' sets streams for the TLS implementation specifying the receivers for 
        a message with a certain message id
        
        Input:  env:                   AutomotiveEnvironmentSpec: specification of the Environment
                new_stream:            MessageStream
        Output: -
    '''
    APICore().set_stream(env, new_stream)

'''===============================================================================
     Project Configuration
==============================================================================='''
    
def apply_timing_functions_set(env, comp_id, timing_function_set):
    ''' Applies a set of timing variables to the environment and the 
        component with id comp_id
        
        Input:  env:                 AutomotiveEnvironmentSpec:      specification of the Environment
                comp_id:             string:                         id of the component
                timing_function_set: TimingFunctionSet:              Set of associations between timing variables and methods
        Output: -
        '''
    APICore().apply_timing_functions_set(env, comp_id, timing_function_set)
    
def connect_monitor(env, monitor, t_period):
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
    APICore().connect_monitor(env, monitor, t_period)

def connect_result_reader(env, my_moni, reader):
    ''' in order to be able to read out results from the simulation 
        an instance of ResultReader has to be created and connected to
        the monitor    
        
        Input:  env:               AutomotiveEnvironmentSpec:          specification of the Environment
                monitor:           Monitor                             monitor object that obtains information from environment
                reader:            ResultReader                        result reader that will get the monitor values relevant for him forwarded
        Output: -     
    '''
    APICore().connect_result_reader(env, my_moni, reader)
    
def save_env_spec(env, filepath):
    ''' saves the environment to a file. Currently not 
        working
        
        Input:  env:                 AutomotiveEnvironmentSpec:     specification of the Environment
                filepath:            string:                        path to the file to be saved
        Output: -
    '''
    APICore().save_env_spec(env, filepath)
    
def load_env_spec(filepath):
    ''' loads the environment that was created from 
        a file. Currently not working
        
        Input:  filepath:                  string                         path to the file to be loaded
        Output: my_env:                    AutomotiveEnvironmentSpec:     specification of the Environment 
    ''' 
    return APICore().load_env_spec(filepath)

    