
class SimParam(object):
    '''
    This class is meant as an interface between the setup of the 
    environment and the realization of the environment
    
    E.g. later on it should be possible to create an instance of this 
    object holding all information necessary for a certain simulation
    environment
    '''

    def __init__(self):
        
        self.app_lifetime = 1000
        self.ecu_bitrate = 500000
                
        self.ecus = {}
        self.buses = {}
        self.gateways = {}
        self.sec_modules = {}
    
    
    def add_ecu(self, new_ecu):
        ''' adds an ecu to the simulation environment'''
        if not new_ecu.ecu_id in self.ecus:
            self.ecus[new_ecu.ecu_id] = new_ecu
        return new_ecu

    
    def add_bus(self, new_bus):
        ''' adds a bus to the simulation environment'''
        if not new_bus.comp_id in self.buses:
            self.buses[new_bus.comp_id] = new_bus
        return new_bus
           
     
    def connect_list(self, bus, ecu_list):
        ''' connects a list of AbstractECU objects to the given
            bus'''
        for ecu in ecu_list:
            self.connect(bus, ecu)
    
    
    def connect(self, bus, ecu):
        ''' connects an ECU to a bus'''        
        if bus not in self.buses.values() or ecu not in self.ecus.values():
            return        
        bus.connect_ecu(ecu)
        ecu.connect_to(bus)
    

        
            