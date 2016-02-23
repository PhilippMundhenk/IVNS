
import simpy
from config import project_registration as proj
from tools.ecu_logging import ECULogger
import logging
import traceback

class AutomotiveEnvironment(object):
    '''
    consists of:
    ECUs
    Busses
    Bus Koppler
    SecurityModules
    BusMessages
    '''

    def __init__(self):  

        ''' 1. Create the Environment'''            
        self._sim_env = simpy.Environment()   
          
        self._app_lifetime = proj.APP_LIFETIME

        ''' 2. Characteristics of System'''
        self.bitrate = 1000000  # 1 Mbit/s

        ''' 3. Components of Environment '''
        self.ecus = {}  # key: id, value: object
        self.gateways = {}  # key: id, value: object
        self.buses = {}  # key: id, value: object
        self.sec_modules = {}  # key: id, value: object
    
    
    def get_env(self):
        return self._sim_env
            
    def set_env(self, env):
        self._sim_env = env
            
    
    def setup_from_sim_param(self, sim_param):
        ''' read from parameter'''
        self._app_lifetime = sim_param.app_lifetime
        
        self.ecus = sim_param.ecus
        self.buses = sim_param.buses
        self.sec_modules = sim_param.sec_modules
        self.gateways = sim_param.gateways

    
    def start(self, monitor=False):
        
        ''' 1. Start application layer of ECU s'''
        for ecu_id in self.ecus:
            if self.ecus[ecu_id].startup_delay:
                self._sim_env.process(self._start_delayed(self.ecus[ecu_id]))
            else:
                self._sim_env.process(self.ecus[ecu_id].ecuSW.app_lay.main())
                self._sim_env.process(self.ecus[ecu_id].ecuSW.comm_mod.datalink_lay.process())
        
        ''' 2. Start the bus running in parallel to the ECUs '''
        for bus_id in self.buses:
            self._sim_env.process(self.buses[bus_id].process())

        ''' 3. Start the monitor object '''
        if monitor:
            monitor.set_monitor_env(self._sim_env)
            proc = self._sim_env.process(monitor.monitor())
            proc2 = self._sim_env.process(monitor.monitor_publish())
            monitor.set_sim_process(proc)
        
        ''' 4. Start the environmant'''        
        try:
            self._sim_env.run(until=self._sim_env.now + self._app_lifetime)
            del self._sim_env
            
        except AttributeError:
            pass
        except:
            traceback.print_exc()
            ECULogger().log_traceback()
            logging.info("Simulation terminated")
            
    

    def _start_delayed(self, ecu):
        ''' starts the ecu with the defined startup delay
        
            Input:     ecu    AbstractECU    Ecu to be started delayed
            Output:     -
        '''
        yield self._sim_env.timeout(ecu.startup_delay)
        
        self._sim_env.process(ecu.ecuSW.app_lay.main())
        self._sim_env.process(ecu.ecuSW.comm_mod.datalink_lay.process())
    
    
    
    def _extract_ecu_actions(self, buses):
        '''extracts all sending actions from all existing ecus'''
        res_dict = {}
        for bus_id in buses:
            for ecu in buses[bus_id].connected_ecus:
                try:
                    res_dict[bus_id] = ecu.sending_actions + res_dict[bus_id]
                except:
                    res_dict[bus_id] = ecu.sending_actions
        return res_dict
             

             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
             
    ''' Deprecated'''       
    '''def _trans_run(self):
        evtl. unnecessary
        while True:
            yield self._sim_env.timeout(0.001)
            
            1. ECU Software Handler = application Layer, runs parallel to the sending and receiving actions
            for ecu_id in self.ecus:
                self._sim_env.process( self.ecus[ecu_id].ecuSW.app_lay.main() )

            2. ECU Sending Handler -> process all sending actions of all ecus on all busses 
            for bus_id in self.ecu_send_action_sets:
                for send_act in self.ecu_send_action_sets[bus_id]:                    
                    process = self.ecus[send_act.ecu_id].process_send_act(send_act)                    
                    start_delayed(self._sim_env, process, delay = send_act.t_start - self._sim_env.now)                    
                    self.ecus[send_act.ecu_id].sending_actions.remove(send_act)

             2. process all bus actions eventually thereby extending the ecu sending actions 
            
            
            3. update the sending actions of the ecus 
            self.ecu_send_action_sets = self._extract_ecu_actions(self.buses)
            
    '''
    '''-> Todo build in arbitration -> happens in the can controller 
            
            
    Senden nur zu festen Bitzeiten, v.a. wegen Arbitrierung interessant   
            
            
             Software: Communication Layer: checkt die Hardware 
            
            Ablauf (ohne Security):
                1. ECU Software will senden: App_lay: self.trans_layer.sendMessage(longMessage)
                2. Transmission_Lay bekommt diese Info
                3. transsmi_lay sagt transport layer bitte senden
                4. transp_lay: segmentiert bzw. padded Nachricht und sendet diese dann einzeln in The "data"
                5. d.h. transp_lay sendet dann alle Nachrichten als Stream: comm_layer.sendMessages(List of CanMessages("data"))
                6. comm_layer kriegt dann also die Nachrichten uebergeben die zu senden sind also den "Bitstream"
                7. comm_lay fuehrt die Streamauthorization durch (wenn zuvor ECU Authentication passiert ist)
                8. comm_lay sendet den Stream
                9. comm_lay ist fertig mit senden (mehr details spaeter)       
    '''
            
            
        
