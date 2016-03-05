'''
    this Adapter is designed to wrap the sending and receiving activities of the Battery Management extension if
    it is applied.
'''
from tools.singleton import Singleton
import api.ecu_sim_api as api
import copy
from api.core.component_specs import SimpleECUSpec, SimpleBusSpec
from enums.sec_cfg_enum import CAEnum
from components.security.communication.stream import MessageStream
from api.core.api_core import TimingFunctionSet
from components.security.ecu.types.impl_sec_mod_lwa import StdSecurLwSecModTimingFunctions
from components.security.ecu.types.impl_ecu_secure import StdSecurECUTimingFunctions
import logging

class BatManAdministrator(Singleton):
    ''' centrally saves all BatManCANBusAdapter objects
        so that they can be mapped
    '''
    
    def __init__(self):
        ''' constructor '''
        
        self.can_bus_adapter = {}  # key: cell_id, value: BatManCANBusAdapter        
        self._ecu_spec = None  # ecu spec used for all ECUs per default
        self._ecu_class_name = None  # class of the ECU that is to be used
        self._individual_spec = {}  # if one ECU is to use different settings 
        self._monitor = False  # monitor object connected to the environment
        self._result_reader = False  # result reader connected to the monitor
        
        self._view = False  # view connected to the environment 
        self._view_options = []  # options of the view w.g. EventlineViewPlugin
        
        self.q_application = None
        self.active = False
        
    def activate_ecu_simulation(self):
        self.active = True
        
    def adapter_used(self):
        ''' this method returns True if the battery management
            is using this adapter implementation for the can bus 
            connection
            
            Input:   -
            Output:  -
        '''
        # available adapters
        lst = self.can_bus_adapter.keys()
        
        # True if adapters available
        if lst:  
            return True
        else: 
            return False

    def add_view(self, direct_view, view_options):
        ''' adds a view (GUI) to the environment which
            is opened together with the environment
            
            Input:  direct_view        DirectViewer        direct view gui that is to be connected
                    view_options       list                list of GUI Plugins that are to be used
            Output: -        
        '''
        self._view = direct_view
        self._view_options = view_options
    
    def available_can_adapters(self):
        ''' returns all adapters that are connected 
            to this environment
            
            Input:    -
            Output:   adapters    list      list of BatManCANBusAdapter objects that are connected to    
                                            this environment
        '''
        return self.can_bus_adapter.keys()
        
    def set_individual_ecu_spec(self, ecu_spec, ecu_class_name):
        ''' if certain ECUs with certain ECU ids shall have defined
            ecu specs set and be of a defined class, then this method
            sets those ECU Specs individually. 
            
            Input:  ecu_spec        AbstractECUSpec     ECU Spec defining which ECU Ids are to be set
                                                        and which ECU specs should be used for those ECU Ids
                    ecu_class_name  string              name of the class that the ECUs should get assigned
            '''
        for ecu_id in ecu_spec.ecu_id_list:
            self._individual_spec[ecu_id] = [ecu_spec, ecu_class_name]
        
    def set_ecu_spec(self, ecu_spec, ecu_class_name):
        ''' this method sets the ecu spec that will be used per default to
            set the ecu specification
            
            Input:  ecu_spec        AbstractECUSpec         spec that will be used to define the properties of the ECU
                                                            in this ECU Simulation environment
                    ecu_class_name  string                  name of the class that the ECUs should get assigned
            Output: -
        '''
        self._ecu_spec = ecu_spec
        self._ecu_class_name = ecu_class_name
        
    def connect_monitor_reader(self, monitor, result_reader):
        ''' this method connects a Monitor and a ResultReader to the environment
            to be able to extract data from the simulation
            
            Input:  monitor            Monitor         monitor connected to the environment
                    result_reader      ResultReader    result reader connected to the monitor
            Output: -                    
        '''
        self._monitor = monitor
        self._result_reader = result_reader
        
    def prepare_configuration(self, simpy_env, life_time):
        ''' this method prepares the configuration on the side of the 
            ECU simulation. It sets up the defined environment by mapping
            the ECU Ids as they are defined in the battery management system
            on the ECUs and the defined specs. So the constellation used is
            implemented here.
            
            Input:  simpy_env    simpy.Environment        environment used in the battery management system
                    life_time    float                    life time of the simulation
            Output: -
        '''
        # lifetime
        life_time = 50000
                
        # logging
#         api_log_path = os.path.join(os.path.dirname(__file__), "../logs/api.log")
#         api.show_logging(logging.INFO, api_log_path, True)
        
        # create environment
        sim_env = api.create_environment(life_time)
        sim_env.set_env(simpy_env)
        ecu_list = []
        
        # generate a ecu from the ECU specs setting the adapter
        for ecu_id in self.available_can_adapters():            
            # logging.info("ECU ID %s: " % ecu_id)
            
            # define individual ECU Spec 
            ecu_spec = copy.deepcopy(self._ecu_spec)
            ecu_class_name = self._ecu_class_name
            if ecu_id in self._individual_spec:
                ecu_spec = self._individual_spec[ecu_id][0]
                ecu_class_name = self._individual_spec[ecu_id][1]
            ecu_spec.ecu_id_list = [str(ecu_id)]
            
            # create ecu            
            ecu = api.set_ecus(sim_env, 1, ecu_class_name, ecu_spec)[0]
            ecu_list += [ecu]
            
            # connect ecu to adapter
            ecu.connect_adapter(self.can_bus_adapter[ecu_id])
        
        # add security module
        # create ECU specification
        ecu_spec = SimpleECUSpec(['SEC 1'], 200000, 200000)  # 200 KB
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_process', 0)  
        ecu_spec.set_ecu_setting('t_ecu_auth_trigger_intervall', 80000)  
        ecu_spec.set_apply_jitter(0.0001)
        sec_mod_group = api.set_ecus(sim_env, 1, 'SecLwAuthSecurityModule', ecu_spec)
        security_module = sec_mod_group[0]
        
        # connect to one bus
        # create the bus specifications
        bus_spec = SimpleBusSpec(['CAN_0'])
        api.set_busses(sim_env, 1, 'StdCANBus', bus_spec)
        api.connect_bus_by_obj(sim_env, 'CAN_0', ecu_list + sec_mod_group) 
                
        # security constellation
        all_ecu_groups = [ecu_list]
        api.register_ecu_groups_to_secmod(sim_env, sec_mod_group[0].ecu_id, all_ecu_groups)         
        certificate_manager = api.create_cert_manager()
        all_created_ecus = api.ecu_list_from_groups([all_ecu_groups])
        ecu_ids = [str(ecu.ecu_id) for ecu in all_created_ecus]        
        for ecu_id in ecu_ids:
            api.generate_valid_ecu_cert_cfg(certificate_manager, ecu_id, CAEnum.CA_L313, security_module.ecu_id, 0, float('inf'))
        api.generate_valid_sec_mod_cert_cfg(certificate_manager, security_module.ecu_id, CAEnum.CA_L313, ecu_ids, 0, float('inf'))
        api.apply_certification(sim_env, certificate_manager)
         
        # define allowed streams -------------------------------------------------------------- TODO very IMPORTANT
        for broadcast_stream_id in [0x0080, 0x0081, 0x0082, 0x0083, 0x0012, 0x0013, 0x0020, 0x00A0, 0x00A1 ]:
            for ecu_id in ecu_ids:
                lst = copy.deepcopy(ecu_ids)
                lst.remove(ecu_id)                
                stream = MessageStream(ecu_id, lst, broadcast_stream_id, float('inf'), 0, float('inf'))
                api.add_allowed_stream(sim_env, security_module.ecu_id, stream)
        #  -------------------------------------------------------------- TODO very IMPORTANT
        
        # set gateways
        api.autoset_gateway_filters(sim_env, sec_mod_group[0].ecu_id)

        # set timing functions
        function_set = TimingFunctionSet()        
        ecu_func_set = StdSecurLwSecModTimingFunctions(main_library_tag='CyaSSL')        
        ecu_func_set.library_tags['t_ecu_auth_reg_msg_validate_cert'] = 'Crypto_Lib_SW'
        function_set.set_mapping_from_function_set(security_module.ecu_id, ecu_func_set)
        api.apply_timing_functions_set(sim_env, security_module.ecu_id, function_set)
        function_set_2 = TimingFunctionSet() 
        ecu_func_set = StdSecurECUTimingFunctions(main_library_tag='CyaSSL')
        ecu_func_set.library_tags['t_adv_msg_secmodcert_enc'] = 'Crypto_Lib_SW'
        for ecu_id in ecu_ids:
            function_set_2.set_mapping_from_function_set(ecu_id, ecu_func_set) 
            api.apply_timing_functions_set(sim_env, ecu_id, function_set_2)
             
        # add monitor
        if self._monitor and self._result_reader:
            api.connect_monitor(sim_env, self._monitor, 0.5)  
            api.connect_result_reader(sim_env, self._monitor, self._result_reader)
             
            # run view if defined 
            if self._view:
                self._view.show(self._result_reader, self._view_options, self.q_application)                

        # run simulation
        api.open_simulation_stop_button(sim_env)
        api.build_simulation(sim_env)
        api.run_simulation(sim_env)
                                
    def add_adapter(self, cell_id, adapter):
        ''' adds a adapter to the simulation environment
            
            Input:  cell_id        string               id of the ECU/CMU that is added to the system
                    adapter        BatManCANBusAdapter  adapter that maps the ECUSimulation environment
                                                        to the Battery management system by intercepting 
                                                        the CANBus sending and receiving process
            Output:  -
        '''
        self.can_bus_adapter[cell_id] = adapter
        
class BatManCANBusAdapter(object):
    '''
    this class is instantiated in the Battery Management environment once per ECU/cell. It is implemented as one
    CAN Bus instance (per cell) that is accessed during the sending and receiving process of each cell. This
    adapter is then mapped onto the ECU Simulation environment by connecting each of those CAN Bus instances 
    to one BatManECU and its application layer. So every time the cell in the Battery Management environment
    invokes the send or received message, the corresponding ECU that resembles this cell is called in the 
    ecu simulation environment.
    '''
    
    # message ids definitions for the battery management system
    CAN_SOC_BROADCAST = [0x0080, 32]  # ('TARGET':'BROADCAST', 'ORIGIN':, 'soc' :)
    CAN_VOLTAGE_BROADCAST = [0x0081, 32]  # ('TARGET':'BROADCAST', 'ORIGIN':, 'voltage' :)
    CAN_BLOCK_REQUEST = [0x0082, 16]  # ('TARGET':'BROADCAST', 'ORIGIN':, 'SENDER_ID':, 'RECEIVER_ID':)
    CAN_UNBLOCK_REQUEST = [0x0083, 16]  # ('TARGET':'BROADCAST', 'ORIGIN':, 'SENDER_ID':, 'RECEIVER_ID':)
    CAN_SEND_REQUEST = [0x0012, 0]  # ('TARGET':, 'ORIGIN':)
    CAN_SEND_ACKNOWLEDGE = [0x0013, 64]  # ('TARGET':, 'ORIGIN':, 'transferTime':, 'transferRate')    
    CAN_STATUS_RESPONSE = [0x0020, 24]  # ('TARGET':, 'ORIGIN':, 'STATUS', 'BLOCKERID1', 'BLOCKERID2')
    CAN_BALANCE_CONTROL = [0x00A0, 0]
    CAN_SUPPLY_LOAD_MODE = [0x00A1, 66]
    
    def __init__(self, cmu):
        ''' Constructor
        
            Input:    cmu    CMU    cmu in the battery management system that corresponds to a ECU in the 
                                    ECUSimulation environment
        '''
        # define default ecu specs
        self.ecu_specs = None
        self.cmu = cmu
        
        # register at Administrator
        self.ecu_id = cmu.objectId
        BatManAdministrator().add_adapter(self.ecu_id, self)
    
        # dummy parameters (needed for instantiation)
        self.dataCount = 0
        self.speed = 2
        self.avgSpeed = 2
        
    def CANsend(self, message):
        ''' when a CMU of the battery management system wants to 
            send a message this method is invoked. If this adapter is 
            connected to  a BatManECU this method is overridden with the 
            method that sends in the ECU Environment
            
            Input:     message    CANBusMessage    can bus message that is sent by the batterymanagement
            Output:     -
        '''
        # logging.info('ID: {}, DATA: {}'.format(message.identifier, message.data))
        self.receive(message)
        logging.info("CAN send not overridden")
        
    def receive(self, msg):
        ''' when a CMU of the battery management system 
            receives a message this method is invoked. If this adapter is 
            connected to  a BatManECU this method is overridden with the 
            method that receives messages in the ECU Environment
            It forwards the message received in the ECU Simulation environment
            and pushes it
            
            Input:      -
            Output:     -
        '''
        self.cmu.messageHandler(msg)

    def addMessageSubscriber(self, method):
        ''' dummy'''
        pass
    
