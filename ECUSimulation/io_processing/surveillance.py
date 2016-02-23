
import simpy
import sqlite3 as lite
from tools.ecu_logging import try_ex , ECULogger
from PyQt4.Qt import QObject
from io_processing.surveillance_handler import InputHandlerChain, \
    CheckpointHandler, BufferHandler, CanBusHandler, \
    EventlineHandler, ConstellationHandler, MonitorInput, MonitorTags
from api.core.api_core import APICore
import logging
from tools.general import RefList
# from PyQt4.Qt import QObject

class Monitor(QObject):    
    
    def __init__(self, input_handler_chain=False):   
        QObject.__init__(self)                
        
        self.sim_env = None
        self.monitored = []
        self.t_period = 1
        self.sample_time = 0.5  # Sample time in which the information is read from the objects
        self._show_time = True
        self._last_run_elements = RefList()
        self._init_input_handlers(input_handler_chain)
        
    def set_handler_chain(self, handler_chain):
        ''' this method allows the user to specify which
            information needs to be parsed '''
        self._input_handler = handler_chain

    def show_monitor_time(self, bool_show):
        ''' output the monitor publish time on every call'''
        self._show_time = bool_show 

    def _init_input_handlers(self, input_handler_chain):
        '''
        per default all input handlers are enabled. If the user wishes
        to have only some handlers parsing information a custom 
        InputHandlerChain has to be passed to the constructor
        '''
        
        if input_handler_chain:
            self._input_handler = input_handler_chain.handler()
        else: 
            self._input_handler = InputHandlerChain()
            self._input_handler.add_handler(CheckpointHandler())
            self._input_handler.add_handler(CanBusHandler())
            self._input_handler.add_handler(BufferHandler())
            self._input_handler.add_handler(EventlineHandler())  
            self._input_handler.add_handler(ConstellationHandler())  
            self._input_handler = self._input_handler.handler()
           
    @ try_ex
    def push_constellation(self, ecu_groups, busses, bus_connections):
        ''' this method receives the initial constellation of the 
            environment and publishes it to the handlers 
        
            Input:  ecu_groups        list        list of lists: [[ecu_list, ecu_spec],[ecu_list, ecu_spec],...]
                    busses            list        list of lists: [[bus_list, ecu_spec],[bus_list, ecu_spec],...]
                    bus_connections   list        list of lists [[bus_id, ecu_id], [bus_id, ecu_id],...]
            Output: -
        '''        
        # push the constellation
        push_list = [MonitorInput([ecu_groups, busses, bus_connections], MonitorTags.CONSELLATION_INFORMATION, \
                            None, 0, None, None, None, None, None, None)]
        self._input_handler.publish(push_list, RefList())        
            
        # push initial ecu ids
        
        push_list = MonitorInput(APICore()._ecu_list_from_groups(ecu_groups), MonitorTags.ECU_ID_LIST, \
                            None, 0, None, None, None, None, None, None)
        self._input_handler.publish(push_list, RefList())   
            
    
    def subscribe(self, obj, func_name, handlers=None):
        ''' in the specified time interval data will be 
            passed to the function func
            
            Subscribe not to the monitor but to specified handlers of it
            e.g. a GUI
        '''
        handler = self._input_handler
        while handler != None:
            if handler.__class__ in handlers:
                handler.subscribe(obj, func_name)
                print("object: %s subscribed to %s" % (obj, handler))
            handler = handler.next
        
    
    def connect(self, obj):
        ''' connects an arbitrary object to 
            the monitor. Then this object can pass 
            information to the Monitor via the monitor_update method
            
            A connection is only possible if the object is monitorable (i.e.
            has all necessary methods)'''
        try:
            if obj not in self.monitored:                
                # Check if this method is monitorable
                obj.monitor_update()
                self.monitored.append(obj)
                obj.set_monitor(self)            
        except:
            pass
           
    
    def monitor(self):
        ''' Gathering of information'''
        
        while True:
            ''' either invoked once in a certain time frame
                or invoked via force command '''
            try:
                
                ''' 1. Update all values -> write it to list '''
                for obj in self.monitored:
                    monitor_input_lst = obj.monitor_update()                    
                    self._last_run_elements.join(monitor_input_lst)
    
                ''' 2. Timeout'''
                yield self.sim_env.timeout(self.sample_time)
            except simpy.Interrupt:
                pass
            
    
    def monitor_publish(self):
        ''' 
            information is captured continuously and 
            send to the connected methods once in a while             
        '''
        
        while True:
            try:
                
                # get current time                
                if self._show_time:              
                    print("Current time %s " % self.sim_env.now)
                
                # if there is new stuff publish it now 
                self._input_handler.publish(self.sim_env.now, self._last_run_elements)  # calls all publishers in a chain
                
                self._last_run_elements.clear()
                
            except:
                ECULogger().log_traceback()
            
            # wait
            yield self.sim_env.timeout(self.t_period)
                    
     
    def set_monitor_env(self, val):
        self.sim_env = val
    
    
    def set_sample_time(self, t_sample):
        self.sample_time = t_sample
    
    
    def set_period(self, t_period):
        self.t_period = t_period
    
    
    def set_sim_process(self, sim_process):
        self.sim_process = sim_process

    
