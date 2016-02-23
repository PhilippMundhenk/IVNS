from components.base.automotive_component import AutomotiveComponent

class ECUHardware(AutomotiveComponent):
    ''' 
    This class defines the Hardware that is
    running the ECU Software. It defines the 
    performance of the ECU Software Components
    '''
    
    def __init__(self, sim_env, transceive, controller, micro_controller):
        ''' Constructor
            
            Input:    sim_env    simpy.Environment        environment of this component
            Output:   -
        '''
        AutomotiveComponent.__init__(self, sim_env)
        
        # hardware
        self.transceiver = transceive
        self.controller = controller
        self.mic_controller = micro_controller
        
        # hardware cross communication
        self.transceiver.connected_controller = controller
        self.controller.connected_transceiver = transceive
        self.controller.connnected_mic_con = micro_controller
        self.mic_controller.connected_controller = controller