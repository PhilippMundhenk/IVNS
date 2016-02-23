from components.base.automotive_component import AutomotiveComponent


class GatewayHardware(AutomotiveComponent):
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
        
        # cross communication of hardware
        for i in range(len(self.transceiver)):            
            self.transceiver[i].connected_controller = controller[i]
            self.controller[i].connected_transceiver = transceive[i]