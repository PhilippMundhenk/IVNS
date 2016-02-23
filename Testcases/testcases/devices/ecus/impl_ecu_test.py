from components.base.ecu.software.ecu_software import ECUSoftware
from components.security.ecu.software.impl_comm_module_secure import SecureCommModule
from testcases.devices.ecus.impl_app_layer_test import TestApplicationLayer
from components.security.ecu.types.impl_ecu_secure import SecureECU


class TestECU(SecureECU):

    def __init__(self, sim_env=None, ecu_id=None, data_rate=None, size_sending_buffer=None, size_receive_buffer=None):

        # Set Settings
        self.set_settings()
        if sim_env == None: return  # No instantiation

        self.messages = dict()

        # Set SW and HW
        self.applLayer = TestApplicationLayer(sim_env, ecu_id)
        SecureECU.__init__(self, sim_env, ecu_id, data_rate, size_sending_buffer, size_receive_buffer)
        self.ecuSW = ECUSoftware(sim_env, SecureCommModule(sim_env, ecu_id), \
                                  self.applLayer)
        self._connect_hw_sw()

    def get_type_id(self):
        return "Test_ECU"

    def setMessages(self, messages):
        if not(self.applLayer is None):
            self.messages = messages
            self.applLayer.setMessages(messages)

    def getMessages(self):
        return self.messages
    
    def setRandomStartTime(self, on):
        self.ecuSW.app_lay.setRandomStartTime(on)
