'''
Created on May 14, 2015

@author: philipp
'''
import os
from api.core.api_core import TimingFunctionSet
from api.core.component_specs import SimpleECUSpec, SimpleBusSpec, \
    SimpleBusCouplerSpec, TLSECUSpec, RegularECUSpec
from components.security.communication.stream import MessageStream
from components.security.ecu.types.impl_ecu_secure import StdSecurECUTimingFunctions
from components.security.ecu.types.impl_sec_mod_lwa import StdSecurLwSecModTimingFunctions
from components.security.encryption.encryption_tools import EncryptionSize
from enums.sec_cfg_enum import HashMechEnum, AsymAuthMechEnum, AuKeyLengthEnum, \
    SymAuthMechEnum, CAEnum
import numpy as np
from testcases.utilities.archSaver import SaveRandom as SR
from components.security.ecu.types.impl_ecu_tls import StdTLSECUTimingFunctions
from components.security.ecu.types.impl_ecu_tesla import StdTeslaECUTimingFunctions
from config.specification_set import LWASpecPresets, GeneralSpecPreset, \
    TeslaSpecPresets, TlsSpecPresets


class ArchGenerator(object):
    '''
    classdocs
    '''

    def __init__(self, env):
        '''
        Constructor
        '''
        self.env = env

    def createArchitectures(self, numberOfArchitectures, archGeneratorSettings):
        for i in numberOfArchitectures:
            self.architectures[i] = self.createArchitecture(archGeneratorSettings)

        return self.architectures

    def createArchitecture(self, archGeneratorSettings):
        newArchitecture = Architecture()

        '''find number of ECUs, buses, msgs'''
        newArchitecture.ecuType = archGeneratorSettings.ecuType
        newArchitecture.numberOfECUs = SR().ran.randint(archGeneratorSettings.minECU, archGeneratorSettings.maxECU)
        newArchitecture.numberOfBuses = SR().ran.randint(archGeneratorSettings.minBuses, archGeneratorSettings.maxBuses)
        newArchitecture.numberOfMsgs = SR().ran.randint(archGeneratorSettings.minMsgs, archGeneratorSettings.maxMsgs)
        newArchitecture.minMsgID = archGeneratorSettings.minMsgID
        newArchitecture.streamMAD = archGeneratorSettings.streamMAD
        newArchitecture.receiverCoefficient = archGeneratorSettings.receiverCoefficient
        newArchitecture.receiversRandomizationFactor = archGeneratorSettings.receiversRandomizationFactor
        newArchitecture.msgPeriodDistr_ms = archGeneratorSettings.msgPeriodDistr_ms
        newArchitecture.msgSizeDistr_byte = archGeneratorSettings.msgSizeDistr_byte
        
        newArchitecture.authenticated = archGeneratorSettings.authenticated

        print("type of ECU tested: %s" % newArchitecture.ecuType)
        print("number of ECUs: " + str(newArchitecture.numberOfECUs))
        print("number of Buses: " + str(newArchitecture.numberOfBuses))
        print("number of Messages: " + str(newArchitecture.numberOfMsgs))
        print("minMsgID: " + str(newArchitecture.minMsgID))
        print("streamMAD: " + str(newArchitecture.streamMAD))
        print("receiverCoefficient: " + str(newArchitecture.receiverCoefficient))
        print("receiversRandomizationFactor: " + str(newArchitecture.receiversRandomizationFactor))
        
        newArchitecture.ecuLibrary = archGeneratorSettings.ecuLibrary
        newArchitecture.secModLibrary = archGeneratorSettings.secModLibrary

        '''save basic ECU settings'''
        for ecu in range(0, newArchitecture.numberOfECUs):
            newArchitecture.ecus[ecu] = ECU()
            newArchitecture.ecus[ecu].name = 'ECU' + str(ecu)
            newArchitecture.ecus[ecu].bufSizeSend_byte = archGeneratorSettings.bufSizeSend_byte
            newArchitecture.ecus[ecu].bufSizeRcv_byte = archGeneratorSettings.bufSizeRcv_byte

        '''save basic security module settings'''
        newArchitecture.secMods[0] = ECU()
        newArchitecture.secMods[0].name = 'SecMod'
        newArchitecture.secMods[0].bufSizeSend_byte = archGeneratorSettings.bufSizeSend_byte
        newArchitecture.secMods[0].bufSizeRcv_byte = archGeneratorSettings.bufSizeRcv_byte

        '''save basic bus settings'''
        for bus in range(0, newArchitecture.numberOfBuses):
            newArchitecture.buses[bus] = Bus()
            newArchitecture.buses[bus].name = 'CAN' + str(bus)
            
        '''create Msg structures'''
        for msg in range(newArchitecture.minMsgID, newArchitecture.minMsgID + newArchitecture.numberOfMsgs):
            newArchitecture.msgs[msg] = Msg(0, 0)
            newArchitecture.msgs[msg].name = 'Stream ' + str(msg)

        return newArchitecture

    def exportToAPI(self, architecture, api):        
        
        if architecture.ecuType == "lw_auth":
            self.exportLWAuthToAPI(architecture, api)
        
        if architecture.ecuType == "tls":
            self.exportTlsToAPI(architecture, api)
            
        if architecture.ecuType == "tesla":
            self.exportTeslaToAPI(architecture, api)
        
    def exportTlsToAPI(self, architecture, api):
        '''create ECUs'''
        path_ecus = os.path.join(os.path.dirname(__file__), "../devices/ecus")
        api.register_ecu_classes(path_ecus)
        
        print("creating ECUs...")
        for ecu in architecture.ecus:
            ecuSpec = TLSECUSpec([architecture.ecus[ecu].name], architecture.ecus[ecu].bufSizeSend_byte, architecture.ecus[ecu].bufSizeRcv_byte)
            TlsSpecPresets().apply_spec(ecuSpec)
            architecture.ecus[ecu].handle = api.set_ecus(self.env, 1, 'TestTLSECU', ecuSpec)[0]
            architecture.ecus[ecu].handle.set_max_message_number(5)

        '''create buses'''
        print("creating buses...")
        for bus in architecture.buses:
            buses = []
            buses.append(architecture.buses[bus].name)
            busSpec = SimpleBusSpec(buses)
            architecture.buses[bus].handle = api.set_busses(self.env, 1, GeneralSpecPreset().bus_string(), busSpec)
            
        '''create gateway, if necessary'''
        if architecture.numberOfBuses > 1:
            print("creating gateway...")
            ecu_spec = SimpleBusCouplerSpec(['GW', 200, 200])
            ecu_spec.set_ecu_setting('t_transition_process', 0.0001)  # Delay of the gateway
            architecture.gateways[0] = Gateway()
            architecture.gateways[0].handle = api.set_ecus(self.env, 1, 'CANGateway', ecu_spec)[0]
                        
            print("assigning gateway to buses")
            for bus in architecture.buses:
                handles = []
                handles.append(architecture.gateways[0].handle)
                api.connect_bus_by_obj(self.env, architecture.buses[bus].name, handles)
                print("gateway is connected to " + architecture.buses[bus].name)
        
        '''randomly assign ECUs to buses'''
        print("assigning ECUs to buses...")
        for ecu in architecture.ecus:
            handles = []
            handles.append(architecture.ecus[ecu].handle)
            bus = architecture.buses[SR().ran.randint(0, architecture.numberOfBuses - 1)].name
            api.connect_bus_by_obj(self.env, bus, handles)
            print("ECU " + architecture.ecus[ecu].handle.ecu_id + " is on bus " + bus)

        '''set up message streams'''
        # TODO: _Philipp: add distribution coefficients for streams per ECU here
        print("setting up message streams...")
        self.env.msgs = {}

        senders = dict()
        intervals = dict()
        sizes = dict()
        for stream_id in range(architecture.minMsgID, architecture.minMsgID + architecture.numberOfMsgs):
            sender = self.getSender(architecture)
            senders[stream_id] = sender
            receivers = []

            architecture.msgs[stream_id].numberReceivers = architecture.receiverCoefficient * (architecture.numberOfECUs - 1)
            architecture.msgs[stream_id].numberReceivers += SR().ran.randint((-1) * architecture.receiversRandomizationFactor, architecture.receiversRandomizationFactor)
            if architecture.msgs[stream_id].numberReceivers < 1:
                architecture.msgs[stream_id].numberReceivers = 1
            if architecture.msgs[stream_id].numberReceivers > (architecture.numberOfECUs - 1):
                architecture.msgs[stream_id].numberReceivers = architecture.numberOfECUs - 1
#             print("number of receivers: "+str(architecture.msgs[stream_id].numberReceivers))
            while len(receivers) < architecture.msgs[stream_id].numberReceivers:
                randRcvID = SR().ran.randint(0, architecture.numberOfECUs - 1)
                if randRcvID == sender:
                    continue
                if architecture.ecus[randRcvID].handle.ecu_id in receivers:
                    continue
                receivers.append(architecture.ecus[randRcvID].handle.ecu_id)

            sizes[stream_id] = self.selectFromDistr(architecture.msgSizeDistr_byte)
            interval = self.selectFromDistr(architecture.msgPeriodDistr_ms) / 1000
            print("ID: " + str(stream_id) + " interval:" + str(interval) + " size: " + str(sizes[stream_id]) + " sender: " + architecture.ecus[sender].handle.ecu_id + " receivers: " + str(receivers))
            stream = MessageStream(architecture.ecus[sender].handle.ecu_id, receivers, stream_id)
            intervals[stream_id] = interval       
            api.set_stream(self.env, stream)
            
            # TODO Hier die Sender ECU senden lassen
            sender = architecture.ecus[sender].handle
            sender.add_sending(SR().ran.random() * 100, interval, stream_id, "DUMMY MESSAGE", sizes[stream_id])
            
        sends = []
        for ecu in architecture.ecus:
            sends.append(architecture.ecus[ecu].sendingMsgs)
            print("ecu" + str(ecu) + " sends " + str(architecture.ecus[ecu].sendingMsgs))
            
        print("MAD of message distribution: " + str(self.mad(sends)))
                        
        print("setting ECU libraries...")
        t_set2 = TimingFunctionSet()
        ecu_func_set = StdTLSECUTimingFunctions(architecture.ecuLibrary)
        for ecu in architecture.ecus:
            t_set2.set_mapping_from_function_set(architecture.ecus[ecu].handle.ecu_id, ecu_func_set)
            api.apply_timing_functions_set(self.env, architecture.ecus[ecu].handle.ecu_id, t_set2)
        
    def exportTeslaToAPI(self, architecture, api):
        '''create ECUs'''
        path_ecus = os.path.join(os.path.dirname(__file__), "../devices/ecus")
        api.register_ecu_classes(path_ecus)
        
        print("creating ECUs...")
        for ecu in architecture.ecus:
            ecuSpec = RegularECUSpec([architecture.ecus[ecu].name], architecture.ecus[ecu].bufSizeSend_byte, architecture.ecus[ecu].bufSizeRcv_byte)            
            ecuSpec.set_apply_jitter(0.00000001)
            TeslaSpecPresets().apply_spec(ecuSpec)                 
            architecture.ecus[ecu].handle = api.set_ecus(self.env, 1, 'TestTeslaECU', ecuSpec)[0]
            architecture.ecus[ecu].handle.set_max_message_number(5)

        '''create buses'''
        print("creating buses...")
        for bus in architecture.buses:
            buses = []
            buses.append(architecture.buses[bus].name)
            busSpec = SimpleBusSpec(buses)
            architecture.buses[bus].handle = api.set_busses(self.env, 1, GeneralSpecPreset().bus_string(), busSpec)
            
        '''create gateway, if necessary'''
        if architecture.numberOfBuses > 1:
            print("creating gateway...")
            ecu_spec = SimpleBusCouplerSpec(['GW', 200, 200])
            ecu_spec.set_ecu_setting('t_transition_process', 0.0001)  # Delay of the gateway
            architecture.gateways[0] = Gateway()
            architecture.gateways[0].handle = api.set_ecus(self.env, 1, 'CANGateway', ecu_spec)[0]
                        
            print("assigning gateway to buses")
            for bus in architecture.buses:
                handles = []
                handles.append(architecture.gateways[0].handle)
                api.connect_bus_by_obj(self.env, architecture.buses[bus].name, handles)
                print("gateway is connected to " + architecture.buses[bus].name)
        
        '''randomly assign ECUs to buses'''
        print("assigning ECUs to buses...")
        for ecu in architecture.ecus:
            handles = []
            handles.append(architecture.ecus[ecu].handle)
            bus = architecture.buses[SR().ran.randint(0, architecture.numberOfBuses - 1)].name
            api.connect_bus_by_obj(self.env, bus, handles)
            print("ECU " + architecture.ecus[ecu].handle.ecu_id + " is on bus " + bus)

        '''set up message streams'''
        # TODO: _Philipp: add distribution coefficients for streams per ECU here
        print("setting up message streams...")
        self.env.msgs = {}

        senders = dict()
        intervals = dict()
        sizes = dict()
        for stream_id in range(architecture.minMsgID, architecture.minMsgID + architecture.numberOfMsgs):
            sender = self.getSender(architecture)
            senders[stream_id] = sender
            receivers = []

            architecture.msgs[stream_id].numberReceivers = architecture.receiverCoefficient * (architecture.numberOfECUs - 1)
            architecture.msgs[stream_id].numberReceivers += SR().ran.randint((-1) * architecture.receiversRandomizationFactor, architecture.receiversRandomizationFactor)
            if architecture.msgs[stream_id].numberReceivers < 1:
                architecture.msgs[stream_id].numberReceivers = 1
            if architecture.msgs[stream_id].numberReceivers > (architecture.numberOfECUs - 1):
                architecture.msgs[stream_id].numberReceivers = architecture.numberOfECUs - 1
#             print("number of receivers: "+str(architecture.msgs[stream_id].numberReceivers))
            while len(receivers) < architecture.msgs[stream_id].numberReceivers:
                randRcvID = SR().ran.randint(0, architecture.numberOfECUs - 1)
                if randRcvID == sender:
                    continue
                if architecture.ecus[randRcvID].handle.ecu_id in receivers:
                    continue
                receivers.append(architecture.ecus[randRcvID].handle.ecu_id)

            sizes[stream_id] = self.selectFromDistr(architecture.msgSizeDistr_byte)
            interval = self.selectFromDistr(architecture.msgPeriodDistr_ms) / 1000
            start_t = 1600 + SR().ran.random() * 10  # shift it far away from setup because setup may take some time (works also when near but long waiting time)
            print("ID: " + str(stream_id) + " interval:" + str(interval) + " size: " + str(sizes[stream_id]) + " sender: " + architecture.ecus[sender].handle.ecu_id + " receivers: " + str(receivers))
            stream = MessageStream(architecture.ecus[sender].handle.ecu_id, receivers, stream_id, start_time=start_t, sending_interval=interval, disclosure_delay=1)
            intervals[stream_id] = interval       
            api.set_stream(self.env, stream)
            
            # TODO Hier die Sender ECU senden lassen
            sender = architecture.ecus[sender].handle
            sender.add_sending(start_t, interval, stream_id, "DUMMY MESSAGE", sizes[stream_id])
            
        sends = []
        for ecu in architecture.ecus:
            sends.append(architecture.ecus[ecu].sendingMsgs)
            print("ecu" + str(ecu) + " sends " + str(architecture.ecus[ecu].sendingMsgs))
            
        print("MAD of message distribution: " + str(self.mad(sends)))
                        
        print("setting ECU libraries...")
        t_set2 = TimingFunctionSet()
        ecu_func_set = StdTeslaECUTimingFunctions(architecture.ecuLibrary)
        for ecu in architecture.ecus:
            t_set2.set_mapping_from_function_set(architecture.ecus[ecu].handle.ecu_id, ecu_func_set)
            api.apply_timing_functions_set(self.env, architecture.ecus[ecu].handle.ecu_id, t_set2)
        
    def exportLWAuthToAPI(self, architecture, api):
        path_ecus = os.path.join(os.path.dirname(__file__), "../devices/ecus")
        api.register_ecu_classes(path_ecus)

        '''create ECUs'''
        print("creating ECUs...")
        for ecu in architecture.ecus:
            ecuSpec = SimpleECUSpec([architecture.ecus[ecu].name], architecture.ecus[ecu].bufSizeSend_byte, architecture.ecus[ecu].bufSizeRcv_byte)
#             ecuSpec = self.getDefaultECUSpec(ecuSpec)
            LWASpecPresets().apply_spec(ecuSpec, 'ecu')
            ecuSpec.set_authenticated(architecture.authenticated)
            architecture.ecus[ecu].handle = api.set_ecus(self.env, 1, 'TestECU', ecuSpec)[0]

        '''create security module'''
        print("creating security module...")
        secModSpec = SimpleECUSpec([architecture.secMods[0].name], architecture.secMods[0].bufSizeSend_byte, architecture.secMods[0].bufSizeRcv_byte)
        LWASpecPresets().apply_spec(secModSpec, 'sec_mod')
        architecture.secMods[0].handle = api.set_ecus(self.env, 1, 'SecLwAuthSecurityModule', secModSpec)[0]

        '''create buses'''
        print("creating buses...")
        for bus in architecture.buses:
            buses = []
            buses.append(architecture.buses[bus].name)
            busSpec = SimpleBusSpec(buses)
            architecture.buses[bus].handle = api.set_busses(self.env, 1, GeneralSpecPreset().bus_string(), busSpec)
            
        '''create gateway, if necessary'''
        if architecture.numberOfBuses > 1:
            print("creating gateway...")
            ecu_spec = SimpleBusCouplerSpec(['GW', 200, 200])
            ecu_spec.set_ecu_setting('t_transition_process', 0.0001)  # Delay of the gateway
            architecture.gateways[0] = Gateway()
            architecture.gateways[0].handle = api.set_ecus(self.env, 1, 'CANGateway', ecu_spec)[0]
            api.autoset_gateway_filters(self.env, architecture.secMods[0].name)
            
            print("assigning gateway to buses")
            for bus in architecture.buses:
                handles = []
                handles.append(architecture.gateways[0].handle)
                api.connect_bus_by_obj(self.env, architecture.buses[bus].name, handles)
                print("gateway is connected to " + architecture.buses[bus].name)
        
        '''randomly assign ECUs to buses'''
        print("assigning ECUs to buses...")
        for ecu in architecture.ecus:
            handles = []
            handles.append(architecture.ecus[ecu].handle)
            bus = architecture.buses[SR().ran.randint(0, architecture.numberOfBuses - 1)].name
            api.connect_bus_by_obj(self.env, bus, handles)
            print("ECU " + architecture.ecus[ecu].handle.ecu_id + " is on bus " + bus)

        '''randomly assign security module to bus'''
        print("assigning security module to bus...")
        handles = []
        handles.append(architecture.secMods[0].handle)
        api.connect_bus_by_obj(self.env, architecture.buses[SR().ran.randint(0, architecture.numberOfBuses - 1)].name, handles)

        '''register ECUs with security module'''
        print("registering ECUs with security module...")
        for ecu in architecture.ecus:
            api.register_ecu_groups_to_secmod(self.env, architecture.secMods[0].handle.ecu_id, [[architecture.ecus[ecu].handle]])  # Last arg: Need to pass multiple ecugroups in a list = [[ecu1,ecu2,ecu3,...],[ecu21, ecu22,...],[],[]]

        '''set up ECU certificates'''
        print("setting up certificates...")
        certeros = api.create_cert_manager()
        ecu_ids = []
        for ecu in architecture.ecus:
            api.generate_valid_ecu_cert_cfg(certeros, architecture.ecus[ecu].handle.ecu_id, CAEnum.CA_L313, architecture.secMods[0].handle.ecu_id, 0, float('inf'))
            ecu_ids.append(architecture.ecus[ecu].handle.ecu_id)
        api.generate_valid_sec_mod_cert_cfg(certeros, architecture.secMods[0].handle.ecu_id, CAEnum.CA_L313, ecu_ids, 0, float('inf'))
        api.apply_certification(self.env, certeros)

        '''set up message streams'''
        # TODO: _Philipp: add distribution coefficients for streams per ECU here
        print("setting up message streams...")
        self.env.msgs = {}

        senders = dict()
        intervals = dict()
        sizes = dict()
        for stream_id in range(architecture.minMsgID, architecture.minMsgID + architecture.numberOfMsgs):
            sender = self.getSender(architecture)
            senders[stream_id] = sender
            receivers = []

            architecture.msgs[stream_id].numberReceivers = architecture.receiverCoefficient * (architecture.numberOfECUs - 1)
            architecture.msgs[stream_id].numberReceivers += SR().ran.randint((-1) * architecture.receiversRandomizationFactor, architecture.receiversRandomizationFactor)
            if architecture.msgs[stream_id].numberReceivers < 1:
                architecture.msgs[stream_id].numberReceivers = 1
            if architecture.msgs[stream_id].numberReceivers > (architecture.numberOfECUs - 1):
                architecture.msgs[stream_id].numberReceivers = architecture.numberOfECUs - 1
#             print("number of receivers: "+str(architecture.msgs[stream_id].numberReceivers))
            while len(receivers) < architecture.msgs[stream_id].numberReceivers:
                randRcvID = SR().ran.randint(0, architecture.numberOfECUs - 1)
                if randRcvID == sender:
                    continue
                if architecture.ecus[randRcvID].handle.ecu_id in receivers:
                    continue
                receivers.append(architecture.ecus[randRcvID].handle.ecu_id)

            sizes[stream_id] = self.selectFromDistr(architecture.msgSizeDistr_byte)
            interval = self.selectFromDistr(architecture.msgPeriodDistr_ms) / 1000
            print("ID: " + str(stream_id) + " interval:" + str(interval) + " size: " + str(sizes[stream_id]) + " sender: " + architecture.ecus[sender].handle.ecu_id + " receivers: " + str(receivers))
            stream = MessageStream(architecture.ecus[sender].handle.ecu_id, receivers, stream_id, float('inf'), 0, float('inf'), interval)
            api.add_allowed_stream(self.env, architecture.secMods[0].handle.ecu_id, stream)
            intervals[stream_id] = interval
            
        sends = []
        for ecu in architecture.ecus:
            sends.append(architecture.ecus[ecu].sendingMsgs)
            print("ecu" + str(ecu) + " sends " + str(architecture.ecus[ecu].sendingMsgs))
            
        print("MAD of message distribution: " + str(self.mad(sends)))
            
        messages = dict()
        for ecu in architecture.ecus:
            messages[ecu] = dict()
            
        for id in senders:
            messages[senders[id]] = architecture.ecus[senders[id]].handle.getMessages()
            if messages[senders[id]] == None:
                messages[senders[id]] = dict()
            messages[senders[id]][id] = Msg(intervals[id], sizes[id])
        
        for ecu in architecture.ecus:
            architecture.ecus[ecu].handle.setRandomStartTime(architecture.authenticated)
        
        for ecu in architecture.ecus:
            architecture.ecus[ecu].handle.setMessages(messages[ecu])
            
        '''set libraries'''
        print("setting security module library...")
        t_set = TimingFunctionSet()
        ecu_func_set = StdSecurLwSecModTimingFunctions(architecture.secModLibrary)
                
        t_set.set_mapping_from_function_set(architecture.secMods[0].handle.ecu_id, ecu_func_set)
        api.apply_timing_functions_set(self.env, architecture.secMods[0].handle.ecu_id, t_set)

        print("setting ECU libraries...")
        t_set2 = TimingFunctionSet()
        ecu_func_set = StdSecurECUTimingFunctions(architecture.ecuLibrary)
        
        
        for ecu in architecture.ecus:
            t_set2.set_mapping_from_function_set(architecture.ecus[ecu].handle.ecu_id, ecu_func_set)
            api.apply_timing_functions_set(self.env, architecture.ecus[ecu].handle.ecu_id, t_set2)

    def getDefaultECUSpec(self, ecuSpec):
#         return ecuSpec
#         '''===========================================================================
#             Sending sizes
#         ==========================================================================='''
#         ecuSpec.set_ecu_setting('p_ecu_cert_sending_size', 1300)
# 
#         '''===========================================================================
#              Certification
#         ==========================================================================='''
#         ecuSpec.set_ecu_setting('p_ecu_auth_cert_ca_len', 3)
#         ecuSpec.set_ecu_setting('p_ecu_auth_cert_hash_mech', HashMechEnum.MD5)
#         ecuSpec.set_ecu_setting('p_ecu_auth_cert_hash_unsigned_size', 16)
#         ecuSpec.set_ecu_setting('p_ecu_auth_cert_enc_mech', AsymAuthMechEnum.RSA)
#         ecuSpec.set_ecu_setting('p_ecu_auth_cert_enc_keylen', AuKeyLengthEnum.bit_1024)
#         ecuSpec.set_ecu_setting('p_ecu_auth_cert_hash_signed_size', EncryptionSize().output_size(16, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_1024, 'SIGN'))
# 
#         '''===========================================================================
#              ECU Authentication
#         ==========================================================================='''
#         ecuSpec.set_ecu_setting('p_ecu_sym_key_alg', SymAuthMechEnum.AES)
#         ecuSpec.set_ecu_setting('p_ecu_sym_key_keylen', AuKeyLengthEnum.bit_128)
# 
#         '''===========================================================================
#              Stream Authorization
#         -> Optional
#         ==========================================================================='''
#         
#         ecuSpec.set_ecu_setting('p_stream_hold', False)  # Define holding behaviour per ECU
#         ecuSpec.set_ecu_setting('p_stream_req_min_interval', 30)

        return ecuSpec

    def getDefaultSecModSpec(self, secModSpec):
#         return secModSpec
#         '''===========================================================================
#             Sending sizes
#         ==========================================================================='''
#         secModSpec.set_ecu_setting('p_sec_mod_cert_size', 1300)
# 
#         '''===========================================================================
#              Certification
#         ==========================================================================='''
#         secModSpec.set_ecu_setting('p_sec_mod_cert_ca_len', 3)    
#         secModSpec.set_ecu_setting('p_sec_mod_cert_hashing_mech', HashMechEnum.MD5)  
#         secModSpec.set_ecu_setting('p_sec_mod_cert_enc_mech', AsymAuthMechEnum.RSA)  
#         secModSpec.set_ecu_setting('p_sec_mod_cert_enc_keylen', AuKeyLengthEnum.bit_1024) 
#         secModSpec.set_ecu_setting('p_sec_mod_cert_hash_size', 16)  # Size of the hash to be signed
#         secModSpec.set_ecu_setting('p_ecu_auth_cert_hash_unsigned_size', 1300)  
#         
#         '''===========================================================================
#              ECU Authentication
#         ==========================================================================='''
#         secModSpec.set_ecu_setting('p_reg_msg_hash_alg', HashMechEnum.MD5)
#         secModSpec.set_ecu_setting('p_reg_msg_inner_enc_method', AsymAuthMechEnum.ECC)
#         secModSpec.set_ecu_setting('p_reg_msg_inner_enc_keylen', AuKeyLengthEnum.bit_256)
#         secModSpec.set_ecu_setting('p_reg_msg_inner_content_size', 100)
#         secModSpec.set_ecu_setting('p_reg_msg_outter_enc_alg', AsymAuthMechEnum.ECC)
#         secModSpec.set_ecu_setting('p_reg_msg_outter_enc_keylen', AuKeyLengthEnum.bit_256)
#         secModSpec.set_ecu_setting('p_ecu_auth_conf_msg_size', 50)
# 
#         '''===========================================================================
#              Stream Authorization
#         ==========================================================================='''
#         secModSpec.set_ecu_setting('p_req_msg_content_size', 50)
#         secModSpec.set_ecu_setting('p_grant_msg_content_size', 80)
# 
#         secModSpec.set_ecu_setting('p_str_auth_ses_key_enc_alg', SymAuthMechEnum.AES)
#         secModSpec.set_ecu_setting('p_str_auth_ses_key_enc_keylen', AuKeyLengthEnum.bit_128)
#         secModSpec.set_ecu_setting('p_str_auth_ses_key_validity', 20000)
# 
#         secModSpec.set_ecu_setting('t_ecu_auth_trigger_process', 100)
#         secModSpec.set_ecu_setting('t_ecu_auth_trigger_intervall', float('inf'))

        return secModSpec

    def mad(self, arr):
        """ Median Absolute Deviation: a "Robust" version of standard deviation.
            Indices variability of the sample.
            https://en.wikipedia.org/wiki/Median_absolute_deviation 
        """
        arr = np.ma.array(arr).compressed()  # should be faster to not use masked arrays.
        med = np.median(arr)
        return np.median(np.abs(arr - med))

    def getSender(self, architecture):
        mad_target = architecture.streamMAD * architecture.numberOfMsgs
        sends = []
        for ecu in architecture.ecus:
            sends.append(architecture.ecus[ecu].sendingMsgs)
        old_mad = self.mad(sends)
        
        new_mad = 0
        for e in architecture.ecus:
            tryECU = e
            architecture.ecus[tryECU].sendingMsgs += 1
            sends = []
            for ecu in architecture.ecus:
                sends.append(architecture.ecus[ecu].sendingMsgs)
            new_mad = self.mad(sends)
            if abs(new_mad - mad_target) < abs(old_mad - mad_target):
                return tryECU
            
            architecture.ecus[tryECU].sendingMsgs -= 1
        
        tryECU = SR().ran.randint(0, architecture.numberOfECUs - 1)
        architecture.ecus[tryECU].sendingMsgs += 1
        return tryECU
    
    def selectFromDistr(self, distr):
        rand = SR().ran.randint(0, 100)
        cnt = 0
        for item, prob in distr:
            cnt += prob
            if cnt >= rand:
                return item
        return distr[-1]
    
class Gateway(object):
    name = ""
    
class Bus(object):
    name = ""

class ECU(object):
    name = ""
    bufSizeSend_byte = 0
    bufSizeRcv_byte = 0
    sendingMsgs = 0
    
class Msg(object):
    
    def __init__(self, interval, size):
        self.interval = interval
        self.size = size
    
    name = ""
    numberReceivers = 0
    size = 0
    interval = 0

class Architecture(object):
    numberOfECUs = 0
    numberOfBuses = 0
    numberOfMsgs = 0
    minMsgID = 0
    ecus = dict()
    secMods = dict()
    buses = dict()
    gateways = dict()
    msgs = dict()
    receiverCoefficient = 0
    streamMAD = 0
    ecuType = 'lw_auth'

    def getSecurityModuleID(self):
        return self.secMods[0].handle.ecu_id

    def getECUs(self):
        return self.ecus

class ArchGeneratorSettings(object):

    def __init__(self):
        '''
        Constructor
        '''

    def setECUType(self, ecuType):
        self.ecuType = ecuType

    def setMaxNumberECU(self, maxECU):
        self.maxECU = maxECU

    def setMinNumberECU(self, minECU):
        self.minECU = minECU

    def setECUBufSizeSend(self, bufSize_byte):
        self.bufSizeSend_byte = bufSize_byte

    def setECUBufSizeReceive(self, bufSize_byte):
        self.bufSizeRcv_byte = bufSize_byte

    def setMaxNumberBuses(self, maxBuses):
        if maxBuses == 0:
            maxBuses = 1
        self.maxBuses = maxBuses

    def setMinNumberBuses(self, minBuses):
        if minBuses == 0:
            minBuses = 1
        self.minBuses = minBuses

    def setMaxNumberMessages(self, maxMsgs):
        self.maxMsgs = maxMsgs

    def setMinNumberMessages(self, minMsgs):
        self.minMsgs = minMsgs
        
    def setMinMsgID(self, minMessageID):
        self.minMsgID = minMessageID
        
    def setMessageSizeDistribution(self, distribution):
        self.msgSizeDistribution = distribution

    def setStreamsPerECUMAD(self, streamCoefficient):
        '''
        Coefficient of 1 means that all streams are sent from 1 ECU, coefficient of 0 means streams are equally distributed
        '''
        self.streamMAD = streamCoefficient

    def setReceiversPerStreamCoefficient(self, receiverCoefficient):
        '''
        Coefficient of 1 means that all streams are received by all ECUs, coefficient of 0 means each stream has only one receiverCoefficient
        '''
        self.receiverCoefficient = receiverCoefficient

    def setECULibrary(self, main_library_tag):
        self.ecuLibrary = main_library_tag

    def setSecModLibrary(self, main_library_tag):
        self.secModLibrary = main_library_tag

    def setReceiversPerStreamRandomizationFactor(self, factor):
        self.receiversRandomizationFactor = factor
        
    def setMsgPeriodDistr_ms(self, distr):
        self.msgPeriodDistr_ms = distr

    def setMsgSizeDistr_byte(self, distr):
        self.msgSizeDistr_byte = distr

    def setAuthenticated(self, authenticated):
        self.authenticated = authenticated
