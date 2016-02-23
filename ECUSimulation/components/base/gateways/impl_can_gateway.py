from components.base.ecu.types.abst_ecu import AbstractECU
from components.base.ecu.hardware.impl_transceiver_std import StdTransceiver
from components.base.ecu.hardware.impl_controller_can_std import StdCanController
from components.base.ecu.software.ecu_software import ECUSoftware
from components.base.ecu.hardware.impl_micro_controller_std import StdMicrocontroller
from components.base.ecu.software.impl_app_layer_simple import SimpleApplicationLayer
from components.base.ecu.hardware.ecu_hardware import ECUHardware
from components.base.ecu.software.impl_comm_module_simple import StdCommModule
import config.timing_registration as time
from components.base.ecu.software.impl_physical_layers import StdPhysicalLayer
from tools.general import General as G
import uuid
from io_processing.surveillance_handler import MonitorTags, MonitorInput
from components.base.ecu.software.impl_datalink_layers import RapidDatalinkLayer, \
    StdDatalinkLayer
from config.specification_set import GeneralSpecPreset


class CANGateway(AbstractECU):
    ''' Simply receives a signal and transmits it to all connected Busses '''

    def __init__(self, sim_env=None, ecu_id=None, data_rate=None):
        ''' Constructor
            
            Input:    sim_env    simpy.Environment        environment of this component
                      ecu_id     string                   id of the corresponding AbstractECU
                      data_rate  float                    datarate of the ecu
            Output:   -
        '''
        self._GATEWAY = True
        
        # set settings
        self.set_settings()
        self._connected_busses = []        
        self._transceivers = []         
        self._controller = []            
        self._physical_layer = []
        self._datalink_layer = []
        self._trans_bus_filter_values = {}
        self._trans_bus_dep_filter_active = False
        self._bus_dep_filter_active = False
        self._filter_values = False  
        self._bus_filter_values = {}  # key: Can ID value: lst allowed msg ids
        
        # create hardware and software
        if sim_env == None: return  # no instantiation        
        AbstractECU.__init__(self, sim_env, uuid.uuid4(), data_rate)           
        self.ecuHW = ECUHardware(sim_env, StdTransceiver(sim_env), StdCanController(sim_env), StdMicrocontroller(sim_env))
        self.ecuSW = ECUSoftware(sim_env, StdCommModule(sim_env), SimpleApplicationLayer(sim_env, ecu_id))
        self._connect_hw_sw()        
        self._override_methods(self.ecuHW.transceiver)    

        # project parameters           
        self.GW_TRANSITION_PROCESS = time.GW_TRANSITION_PROCESS

    
    def set_transmit_filter_from_can_dict(self, can_dict):
        ''' installs a filter at the HW that is connected
            to the corresponding bus. Only defined messages will
            be forwarded
            key: can_id
            value: values to be forwarded
            
            Input:     can_dict    dictinary    key: can_id; value: values to be forwarded
            Output:     -
        '''
        self._trans_bus_filter_values = can_dict
        self._trans_bus_dep_filter_active = True
        
    
    def set_filter_from_can_dict(self, can_dict):
        ''' installs a filter at the HW that is connected
            to the corresponding bus. Only the defined messages
            will be received from the bus
            key: can_id
            value: values to be filtered
            
            Input:     can_dict    dictinary    key: can_id; value: values to be filtered
            Output:     -
        '''
        self._bus_dep_filter_active = True
        self._bus_filter_values = can_dict
        
        for ky in self._bus_filter_values:
            trans = self._trans_by_bus_id(ky)
            if trans == None: return
            trans.install_filter(self._bus_filter_values[ky])

    
    def install_filter(self, message_id_list):
        ''' installs a filter for all Busses on each
            transceiver at every port
            
            Input:     message_id_list    list    list of message ids that are allowed
            Output:    -
        '''       
        self.ecuHW.transceiver.install_filter(message_id_list)
        
        for trans in self._transceivers:
            trans.install_filter(message_id_list)
            
        self._filter_values = message_id_list
        
    
    def get_type_id(self):
        ''' returns the id of this ECU type
        
            Input:    -
            Output:   ecu_type    string    type of this ECU; e.g.'TLSECU'
        '''
        return "CAN_Gateway"
    
    
    def set_settings(self):
        ''' sets the initial setting association between the settings variables
            and the actual parameter
        
            Input:   -
            Output:  -
        '''
        self.settings = {}
        
        self.settings['t_transition_process'] = 'GW_TRANSITION_PROCESS'
        
    
    def _override_methods(self, transceiver):
        ''' overrides the transceivers get method
            to be able to intercept incoming messages
            
            Input:    transceiver    AbstractTransceiver    transceiver of the gateway
            Output:    -
        '''
        transceiver.get = self._transceiver_get
    
    
    def _trans_by_bus_id(self, bus_id):
        ''' returns the transceiver which is connected
            to the bus with the given bus_id
        
            Input:    bus_id         string                identifier of the bus
            Output:   transceiver    AbstractTransceiver   transceiver that is connected to the bus
        
        '''
        for transceiver in self._transceivers:
            if transceiver.connected_bus.comp_id == bus_id:
                return transceiver
        return None
                
    
    
    def _transceiver_get(self, message):
        ''' this method overrides the get method of the transceiver and
            directly redirects traffic coming from one transceiver to all
            other connected transceivers
            Thereby if specified, traffic in chosen directions is
            filtered by letting pass only messages with specified 
            message identifiers
            
            Input:    message    CANSegMessage    message that is sent over this transceiver
            Output:    -            
        ''' 
         
        # filter messages
        if self.ecuHW.transceiver.filter_active:
            if not message.message_identifier in self.ecuHW.transceiver.allowed_items: return
        
        # bus dependent filter active: bus dependent elements are filtered out
        if self._bus_dep_filter_active:
            trans = self._trans_by_bus_id(message.current_bus)
            if trans == None: return
            if not message.message_identifier in trans.allowed_items:
                return
         
        # forward to data link layer
        for i in range(len(self._connected_busses)):
              
            # not to sender 
            if self._connected_busses[i].comp_id == message.current_bus: 
                continue
            
            # Set the gateway Id to avoid loops
            try: message.gw_id += [self.ecu_id]
            except: message.gw_id = [self.ecu_id]
            
            # forward message (if allowed)
            if self._filter_forward(message.message_identifier, self._connected_busses[i].comp_id): continue                            
            self.sim_env.process(self.put_delayed_message(self._datalink_layer[i], message))
       
    
    def monitor_update(self):
        ''' returns the input for the monitor 
        
            Input:    -
            Output:   monitor_list    list    List of MonitorInput objects
        '''
        
        lst = []
        
        for i in range(len(self._connected_busses)):
            
            try:
                # buffer information
                items_1 = len(self._datalink_layer[i].controller.receive_buffer.get_bytes())
                items_2 = len(self._datalink_layer[i].controller.transmit_buffer.get_bytes())
                
                lst.append(MonitorInput(items_1, MonitorTags.BT_ECU_RECEIVE_BUFFER, "BUS (%s) GW_%s" % (self._connected_busses[i].comp_id, self._ecu_id), self.sim_env.now))
                lst.append(MonitorInput(items_2, MonitorTags.BT_ECU_TRANSMIT_BUFFER, "BUS (%s) GW_%s" % (self._connected_busses[i].comp_id, self._ecu_id), self.sim_env.now))
            except:
                pass
                    
        return lst
       
       
    
    def put_delayed_message(self, dll_layer, message):
        ''' this method puts the passed message on the 
            passed data link layer after waiting the
            specified gateway delay
            
            Input:    message    CANFDSegMessage    message that is forwarded
            Output:    -
        '''
        G().to_t(self.sim_env, self.GW_TRANSITION_PROCESS * self._jitter, 'GW_TRANSITION_PROCESS', self.__class__.__name__, self)
        yield self.sim_env.timeout(self.GW_TRANSITION_PROCESS * self._jitter)  
        self.sim_env.process(dll_layer.put_msg(message))
        
    @property
    
    def connected_bus(self):
        return self._connected_busses
    
    @connected_bus.setter
    
    def connected_bus(self, new_bus):
        ''' if called adds a new port to this 
            gateway. This port has all three layers
            and a whole hardware equipment 
            
            Input:    new_bus    CANBus    bus to be connected to new port
            Output:    -
        '''
        if new_bus != None:
            
            # create whole layer package per connected Bus            
            self._connected_busses.append(new_bus)
                        
            # create layers
            
            # preset used
            if GeneralSpecPreset().enabled: 
                self._transceivers.append(StdTransceiver(self.sim_env))         
                self._controller.append(StdCanController(self.sim_env))            
                self._physical_layer.append(GeneralSpecPreset().physical_layer(self.sim_env))
                self._datalink_layer.append(GeneralSpecPreset().datalink_layer(self.sim_env))
            else:
                self._transceivers.append(StdTransceiver(self.sim_env))         
                self._controller.append(StdCanController(self.sim_env))            
                self._physical_layer.append(StdPhysicalLayer(self.sim_env))
                self._datalink_layer.append(StdDatalinkLayer(self.sim_env))
            

            # interconnect new layers
            self._datalink_layer[-1].controller = self._controller[-1]
            self.sim_env.process(self._datalink_layer[-1].process())            
            self._datalink_layer[-1].physical_lay = self._physical_layer[-1]
            self._physical_layer[-1].transceiver = self._transceivers[-1]             
            self._physical_layer[-1].transceiver.connected_bus = self._connected_busses[-1]            
        
            # intercept gateway methods
            self._override_methods(self._physical_layer[-1].transceiver)

            # activate filter
            if self._filter_values:  # install the fixed filter for all ecus
                self._transceivers[-1].install_filter(self._filter_values)
            
            if new_bus.comp_id in self._bus_filter_values:  # install the filter for special busses
                self._transceivers[-1].install_filter(self._bus_filter_values[new_bus.comp_id])

    def _filter_forward(self, message_id, bus_id):
        ''' filters messages in the forward direction. Returns
            true if the message has to be filtered.
            
            Input:    message_id    integer    message id of the  message considered
                      bus_id        string     Identifier of the bus under consideration
            Output:     -            
        '''     
        if self._trans_bus_dep_filter_active:
            try:
                allowed = self._trans_bus_filter_values[bus_id]
            except:
                return True                
            if not message_id in allowed:
                return True    
        return False
