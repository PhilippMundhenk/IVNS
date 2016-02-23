'''
Created on 12 Jun, 2015

@author: artur.mrowca
'''
from enum import Enum
from PyQt4.Qt import QObject
from PyQt4 import QtCore
from tools.ecu_logging import ECULogger
import copy
        
class AbstractInputHandler(QObject):
    
    publish_infos_sig = QtCore.pyqtSignal(list)
    
    def __init__(self):   
        QObject.__init__(self)
        self.next = None
        self._recs = []        

    def set_next(self, input_handler):
        self.next = input_handler

    def subscribe(self, obj, func_name):
        ''' 
        all objects that subscribe to this function
        publish their information here        
         '''
        self._recs.append(obj)
        exec('self.publish_infos_sig.connect(obj.%s)' % func_name)

    def publish(self, cur_time, monitor_inputs):
        
        # emit the signal to all connected receivers then call next publish
        try:
            
            res = [[monitor_input.time_called, str(monitor_input.mon_id), str(monitor_input.asc_id), str(monitor_input.tag), monitor_input.msg_id, str(monitor_input.message), \
                    monitor_input.msg_size, monitor_input.stream_id, str(monitor_input.unique_id), str(monitor_input.data)] \
                   for monitor_input in monitor_inputs.get() if monitor_input.tag in self._get_tags()]  
            
            # if there is a result only:
            if res: 
                self.publish_infos_sig.emit(copy.deepcopy(res))  
        except:
            ECULogger().log_traceback()
        
        if self.next != None:
            self.next.publish(cur_time, monitor_inputs)
            
    def _get_tags(self):
        return []            
  
class BufferHandler(AbstractInputHandler):
    
    def __init__(self):   
        AbstractInputHandler.__init__(self)   
        
    def _get_tags(self):
        return [MonitorTags.BT_ECU_RECEIVE_BUFFER, MonitorTags.BT_ECU_TRANSMIT_BUFFER]
        
class CanBusHandler(AbstractInputHandler):
    
    def __init__(self):   
        AbstractInputHandler.__init__(self)

    def publish(self, cur_time, monitor_inputs):
        
        # emit the signal to all connected receivers then call next publish
        try:
            res = [[monitor_input.time_called, str(monitor_input.mon_id), str(monitor_input.asc_id), str(monitor_input.tag), monitor_input.msg_id, str(monitor_input.message), \
                    monitor_input.msg_size, monitor_input.stream_id, str(monitor_input.unique_id), str(monitor_input.data)] \
                   for monitor_input in monitor_inputs.get() if monitor_input.tag in self._get_tags()]  

            if res:        
                self.publish_infos_sig.emit(copy.deepcopy([cur_time, res]))  
        except:
            ECULogger().log_traceback()
        
        if self.next != None:
            self.next.publish(cur_time, monitor_inputs)

    def _get_tags(self):
        return  [MonitorTags.CB_DONE_PROCESSING_MESSAGE, MonitorTags.CB_PROCESSING_MESSAGE]
            
class ConstellationHandler(AbstractInputHandler):
    def __init__(self):   
        AbstractInputHandler.__init__(self)
        self.first = True
        
    def publish(self, values, monitor_inputs):
        ''' pushes the initial constellation exactly once
        '''
        try:
            if self.first:                
                self.publish_infos_sig.emit(values)  
                self.first = False
        except:
            pass
        
        if self.next != None:
            self.next.publish(values, monitor_inputs)

    def _get_tags(self):
        return  [MonitorTags.CONSELLATION_INFORMATION]    
        
class EventlineHandler(AbstractInputHandler):
    def __init__(self):   
        AbstractInputHandler.__init__(self)


    def publish(self, values, monitor_inputs):
        ''' pushes the ecu ids or the     
            view
        '''       
        
        try:
            if values.tag == MonitorTags.ECU_ID_LIST:
                self.publish_infos_sig.emit([ecu.ecu_id for ecu in values.data])
            else:
                AbstractInputHandler.publish(self, values, monitor_inputs)
        except:
            try:
                AbstractInputHandler.publish(self, values, monitor_inputs)
            except:
                pass
        
        if self.next != None:
            self.next.publish(values, monitor_inputs)

    def _get_tags(self):
        return  [MonitorTags.CP_SEC_INIT_AUTHENTICATION, \
            MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE, \
            MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE, \
            MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE, \
            MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE, \
            MonitorTags.CP_SEC_CREATED_CMP_HASH_REG_MSG, \
            MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG, \
            MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE, \
            MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE, \
            MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE, \
            MonitorTags.CP_SEC_GENERATED_SESSION_KEY, \
            MonitorTags.CP_SEC_ENCRYPTED_DENY_MESSAGE, \
            MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE, \
            MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE, \
            MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT, \
            MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE, \
            MonitorTags.CP_ECU_START_CREATION_REG_MESSAGE, \
            MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE, \
            MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE, \
            MonitorTags.CP_ECU_SEND_REG_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE, \
            MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE, \
            MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_DENY_MESSAGE, \
            MonitorTags.CP_ECU_DECRYPTED_DENY_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE, \
            MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE, \
            MonitorTags.CP_SESSION_AVAILABLE_SEND_MESSAGE, \
            MonitorTags.CP_SEND_CLIENT_HELLO, \
            MonitorTags.CP_RECEIVE_CLIENT_HELLO, \
            MonitorTags.CP_SEND_ALERT_NO_CIPHERSUITE, \
            MonitorTags.CP_SEND_SERVER_HELLO, \
            MonitorTags.CP_SEND_SERVER_CERTIFICATE, \
            MonitorTags.CP_SEND_SERVER_KEYEXCHANGE,
            MonitorTags.CP_SEND_CERTIFICATE_REQUEST , \
            MonitorTags.CP_SEND_SERVER_HELLO_DONE , \
            MonitorTags.CP_RECEIVE_SERVER_HELLO , \
            MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE , \
            MonitorTags.CP_RECEIVE_SERVER_KEYEXCHANGE , \
            MonitorTags.CP_RECEIVE_CERTIFICATE_REQUEST , \
            MonitorTags.CP_RECEIVE_SERVER_HELLO_DONE , \
            MonitorTags.CP_SERVER_HELLO_DONE_VALIDATED_CERT , \
            MonitorTags.CP_SEND_CLIENT_CERTIFICATE , \
            MonitorTags.CP_INIT_SEND_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_ENCRYPTED_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_GENERATED_MASTERSEC_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_INIT_SEND_CERTIFICATE_VERIFY , \
            MonitorTags.CP_ENCRYPTED_CERTIFICATE_VERIFY , \
            MonitorTags.CP_SEND_CIPHER_SPEC , \
            MonitorTags.CP_INIT_CLIENT_FINISHED , \
            MonitorTags.CP_HASHED_CLIENT_FINISHED , \
            MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED , \
            MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE , \
            MonitorTags.CP_CLIENT_CERTIFICATE_VALIDATED , \
            MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_DECRYPTED_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_RECEIVE_CERTIFICATE_VERIFY , \
            MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY , \
            MonitorTags.CP_GENERATED_MASTER_SECRET_CERT_VERIFY , \
            MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC , \
            MonitorTags.CP_RECEIVE_CLIENT_FINISHED , \
            MonitorTags.CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH , \
            MonitorTags.CP_CLIENT_FINISHED_GENERATED_HASH_PRF , \
            MonitorTags.CP_RECEIVE_SERVER_FINISHED , \
            MonitorTags.CP_SERVER_FINISHED_HASHED_COMPARISON_HASH , \
            MonitorTags.CP_SERVER_FINISHED_GENERATED_HASH_PRF , \
            MonitorTags.CP_INIT_SERVER_FINISHED , \
            MonitorTags.CP_HASHED_SERVER_FINISHED , \
            MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED , \
            MonitorTags.CP_SERVER_AUTHENTICATED , \
            MonitorTags.CP_CLIENT_AUTHENTICATED, \
            MonitorTags.CP_RECEIVE_SIMPLE_MESSAGE, \
            MonitorTags.CP_INIT_EXCHANGE_FIRST_KEY_KN, \
            MonitorTags.CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN, \
            MonitorTags.CP_SETUP_INIT_CREATE_KEYS, \
            MonitorTags.CP_SETUP_FINISHED_CREATE_KEYS, \
            MonitorTags.CP_INIT_TRANSMIT_MESSAGE, \
            MonitorTags.CP_MACED_TRANSMIT_MESSAGE, \
            MonitorTags.CP_RECEIVED_SIMPLE_MESSAGE, \
            MonitorTags.CP_BUFFERED_SIMPLE_MESSAGE, \
            MonitorTags.CP_RETURNED_AUTHENTICATED_SIMPLE_MESSAGE, \
            MonitorTags.CP_RECEIVED_EXCHANGE_FIRST_KEY_KN, \
            MonitorTags.CP_DECRYPTED_EXCHANGE_FIRST_KEY_KN, \
            MonitorTags.CP_CHECKED_KEY_LEGID, \
            MonitorTags.CP_INIT_CHECK_KEY_LEGID, \
            MonitorTags.CP_INIT_VERIFYING_BUFFER_MESSAGE, \
            MonitorTags.CP_FINISHED_VERIFYING_BUFFER_MESSAGE, \
            MonitorTags.CP_SEND_SYNC_MESSAGE, \
            MonitorTags.CP_SEND_SYNC_RESPONSE_MESSAGE, \
            MonitorTags.CP_RECEIVE_SYNC_RESPONSE_MESSAGE]
      
class CheckpointHandler(AbstractInputHandler):
    ''' reads and publishes all Checkpoint Monitor values'''
    
    def __init__(self):   
        AbstractInputHandler.__init__(self)
        
    # override
    def publish(self, cur_time, monitor_inputs):
        
        # emit the signal to all connected receivers then call next publish
        try:
            res = [[monitor_input.time_called, str(monitor_input.mon_id), str(monitor_input.asc_id), str(monitor_input.tag), monitor_input.msg_id, str(monitor_input.message), \
                    monitor_input.msg_size, monitor_input.stream_id, str(monitor_input.unique_id), str(monitor_input.data)] \
                   for monitor_input in monitor_inputs.get() if monitor_input.tag in self._get_tags()]  
            
            self.publish_infos_sig.emit([None, None])  
        except:
            ECULogger().log_traceback()
        
        if self.next != None:
            self.next.publish(cur_time, monitor_inputs)
    
    def _get_tags(self):
        return  [MonitorTags.CP_SEC_INIT_AUTHENTICATION, \
            MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE, \
            MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE, \
            MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE, \
            MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE, \
            MonitorTags.CP_SEC_CREATED_CMP_HASH_REG_MSG, \
            MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG, \
            MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE, \
            MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE, \
            MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE, \
            MonitorTags.CP_SEC_GENERATED_SESSION_KEY, \
            MonitorTags.CP_SEC_ENCRYPTED_DENY_MESSAGE, \
            MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE, \
            MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE, \
            MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT, \
            MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE, \
            MonitorTags.CP_ECU_START_CREATION_REG_MESSAGE, \
            MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE, \
            MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE, \
            MonitorTags.CP_ECU_SEND_REG_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE, \
            MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE, \
            MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_DENY_MESSAGE, \
            MonitorTags.CP_ECU_DECRYPTED_DENY_MESSAGE, \
            MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE, \
            MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE, \
            MonitorTags.CP_SESSION_AVAILABLE_SEND_MESSAGE, \
            MonitorTags.CP_SEND_CLIENT_HELLO, \
            MonitorTags.CP_RECEIVE_CLIENT_HELLO, \
            MonitorTags.CP_SEND_ALERT_NO_CIPHERSUITE, \
            MonitorTags.CP_SEND_SERVER_HELLO, \
            MonitorTags.CP_SEND_SERVER_CERTIFICATE, \
            MonitorTags.CP_SEND_SERVER_KEYEXCHANGE,
            MonitorTags.CP_SEND_CERTIFICATE_REQUEST , \
            MonitorTags.CP_SEND_SERVER_HELLO_DONE , \
            MonitorTags.CP_RECEIVE_SERVER_HELLO , \
            MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE , \
            MonitorTags.CP_RECEIVE_SERVER_KEYEXCHANGE , \
            MonitorTags.CP_RECEIVE_CERTIFICATE_REQUEST , \
            MonitorTags.CP_RECEIVE_SERVER_HELLO_DONE , \
            MonitorTags.CP_SERVER_HELLO_DONE_VALIDATED_CERT , \
            MonitorTags.CP_SEND_CLIENT_CERTIFICATE , \
            MonitorTags.CP_INIT_SEND_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_ENCRYPTED_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_GENERATED_MASTERSEC_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_INIT_SEND_CERTIFICATE_VERIFY , \
            MonitorTags.CP_ENCRYPTED_CERTIFICATE_VERIFY , \
            MonitorTags.CP_SEND_CIPHER_SPEC , \
            MonitorTags.CP_INIT_CLIENT_FINISHED , \
            MonitorTags.CP_HASHED_CLIENT_FINISHED , \
            MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED , \
            MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE , \
            MonitorTags.CP_CLIENT_CERTIFICATE_VALIDATED , \
            MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_DECRYPTED_CLIENT_KEYEXCHANGE , \
            MonitorTags.CP_RECEIVE_CERTIFICATE_VERIFY , \
            MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY , \
            MonitorTags.CP_GENERATED_MASTER_SECRET_CERT_VERIFY , \
            MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC , \
            MonitorTags.CP_RECEIVE_CLIENT_FINISHED , \
            MonitorTags.CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH , \
            MonitorTags.CP_CLIENT_FINISHED_GENERATED_HASH_PRF , \
            MonitorTags.CP_RECEIVE_SERVER_FINISHED , \
            MonitorTags.CP_SERVER_FINISHED_HASHED_COMPARISON_HASH , \
            MonitorTags.CP_SERVER_FINISHED_GENERATED_HASH_PRF , \
            MonitorTags.CP_INIT_SERVER_FINISHED , \
            MonitorTags.CP_HASHED_SERVER_FINISHED , \
            MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED , \
            MonitorTags.CP_SERVER_AUTHENTICATED , \
            MonitorTags.CP_CLIENT_AUTHENTICATED, \
            MonitorTags.CP_RECEIVE_SIMPLE_MESSAGE, \
            MonitorTags.CP_INIT_EXCHANGE_FIRST_KEY_KN, \
            MonitorTags.CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN, \
            MonitorTags.CP_SETUP_INIT_CREATE_KEYS, \
            MonitorTags.CP_SETUP_FINISHED_CREATE_KEYS, \
            MonitorTags.CP_INIT_TRANSMIT_MESSAGE, \
            MonitorTags.CP_MACED_TRANSMIT_MESSAGE, \
            MonitorTags.CP_RECEIVED_SIMPLE_MESSAGE, \
            MonitorTags.CP_BUFFERED_SIMPLE_MESSAGE, \
            MonitorTags.CP_RETURNED_AUTHENTICATED_SIMPLE_MESSAGE, \
            MonitorTags.CP_RECEIVED_EXCHANGE_FIRST_KEY_KN, \
            MonitorTags.CP_DECRYPTED_EXCHANGE_FIRST_KEY_KN, \
            MonitorTags.CP_INIT_CHECK_KEY_LEGID, \
            MonitorTags.CP_CHECKED_KEY_LEGID, \
            MonitorTags.CP_INIT_VERIFYING_BUFFER_MESSAGE, \
            MonitorTags.CP_FINISHED_VERIFYING_BUFFER_MESSAGE, \
            MonitorTags.CP_SEND_SYNC_MESSAGE, \
            MonitorTags.CP_SEND_SYNC_RESPONSE_MESSAGE, \
            MonitorTags.CP_RECEIVE_SYNC_RESPONSE_MESSAGE]
      
class InputHandlerChain(object):
        
    def add_handler(self, handler):
        try:
            self._next_handler.set_next(handler)
        except:
            self._handler = handler
        self._next_handler = handler
        return handler
        
    def handler(self):   
        return self._handler
    
class MonitorInput(object):
    '''
    Keeps the input data of a monitor. Tag defines the type of data arriving
    Possible Tags are MonitorTags    
    '''

    def __init__(self, data, monitor_tag, mon_id=False, time_called=False, asc_id=None, \
                 msg_id=-1, message=None, msg_size=-1, stream_id=-1, unique_id=None):
                
        self.data = data
        self.tag = monitor_tag
        self.mon_id = mon_id        
        self.time_called = time_called
        
        self.calling_object = None
        self.asc_id = asc_id
        self.msg_id = msg_id
        self.message = message
        self.msg_size = msg_size
        self.stream_id = stream_id
        self.unique_id = unique_id
        
class MonitorTags(Enum):
    
    # Buffer Tags
    BT_ECU_TRANSMIT_BUFFER = 1
    BT_ECU_RECEIVE_BUFFER = 2
    
    # Receiving/Sending Times, Message Contents SPAETER MIT CHECKPOINTS ZUSAMMENFUEHREN    
    # Checkpoints - SEC MOD SIDE
    CP_SEC_INIT_AUTHENTICATION = 7  # Sec Mod. initialized authentication
    CP_SEC_RECEIVE_REG_MESSAGE = 8  # Sec Mod receive the registration message
    
    CP_SEC_DECRYPTED_INNER_REG_MESSAGE = 10  # Sec Mod decrypted inner reg Msg
    CP_SEC_DECRYPTED_OUTER_REG_MESSAGE = 11  # Sec Mod decrypted outer reg Msg
    CP_SEC_VALIDATED_ECU_CERTIFICATE = 12  # Sec Mod. validated the ECU Certificate
    CP_SEC_CREATED_CMP_HASH_REG_MSG = 13  # Create the comparision hash for validation of reg msg hash
    CP_SEC_COMPARED_HASH_REG_MSG = 14  # Finished comparing the reg msg hash to the created hash and sends the message

    CP_SEC_RECEIVE_REQ_MESSAGE = 15  # Sec Mod. received the request message
    CP_SEC_DECRYPTED_REQ_MESSAGE = 16  # Sec Mod decrypted the request message

    CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE = 9  # Sec Mod created confirmation message and sends it

    CP_SEC_GENERATED_SESSION_KEY = 17  # Sec Mod. generated the session key
    CP_SEC_ENCRYPTED_DENY_MESSAGE = 18  # Sec. Mod encrypted the deny message
    CP_SEC_ENCRYPTED_GRANT_MESSAGE = 19  # Sec. Mod encrypted the grant message

    # Checkpoints - ECU SIDE
    CP_ECU_RECEIVE_SIMPLE_MESSAGE = 20  # ECU receives a encrypted simple message
    CP_ECU_DECRYPTED_SIMPLE_MESSAGE = 21  # ECU decrypted the received simple message
    
    CP_ECU_INTENT_SEND_SIMPLE_MESSAGE = 22  # ECU decides on comm. module that it wants to send a simple message
    CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE = 23  # ECU encrypted message and sends it
    
    CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT = 24  # ECU receives the SEC Module advertisement
    CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE = 25  # ECU validated the sec. mod. certificate    
    
    CP_ECU_START_CREATION_REG_MESSAGE = 26  # ECU starts to create the registration message
    CP_ECU_CREATED_ECU_KEY_REG_MESSAGE = 27  # ECU created the sym. ECU key
    CP_ECU_ENCRYPTED_INNER_REG_MESSAGE = 28  # ECU encrypted inner reg. msg
    CP_ECU_HASHED_INNER_REG_MESSAGE = 29  # ECU hashed inner reg. msg
    CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE = 30  # ECU encrypted the outer reg. msg
    CP_ECU_SEND_REG_MESSAGE = 31  # ECU sends the reg. message
    
    CP_ECU_RECEIVE_CONF_MESSAGE = 32  # ECU receives a confirmation message
    CP_ECU_DECRYPTED_CONF_MESSAGE = 33  # ECU decrypted the confirmation message
    
    CP_ECU_START_CREATE_REQ_MESSAGE = 34  # ECU Starts creation of request message
    CP_ECU_ENCRYPTED_REQ_MESSAGE = 35  # ECU encrypted the request message and sends it

    CP_ECU_RECEIVE_DENY_MESSAGE = 36  # ECU receives a deny message
    CP_ECU_DECRYPTED_DENY_MESSAGE = 37  # ECU decrypted the deny message

    CP_ECU_RECEIVE_GRANT_MESSAGE = 38  # ECU receives a grant message
    CP_ECU_DECRYPTED_GRANT_MESSAGE = 39  # ECU decrypted the grant message

    CP_ECU_ALREADY_AUTHENTICATED = 40  # The ECU is already authenticated and the message is discareded

    # Checkpoints - TLS
    CP_SESSION_AVAILABLE_SEND_MESSAGE = 43  # There is a session available for this stream and the message is transmitted
    
    CP_SEND_CLIENT_HELLO = 44  # No session is available for that stream. Send the client hello message    
    CP_RECEIVE_CLIENT_HELLO = 45  # Receive the client hello and answer    
    
    CP_SEND_ALERT_NO_CIPHERSUITE = 46  # alert message if the wrong ciphersuite was chosen    
    CP_SEND_SERVER_HELLO = 47  # send the server Hello message        
    CP_SEND_SERVER_CERTIFICATE = 48  # send the server Certificate message    
    CP_SEND_SERVER_KEYEXCHANGE = 49  # send the server Keyexchange message
    CP_SEND_CERTIFICATE_REQUEST = 50  # send the certificate request message
    CP_SEND_SERVER_HELLO_DONE = 51  # send the server Hello done message    

    CP_RECEIVE_SERVER_HELLO = 52
    CP_RECEIVE_SERVER_CERTIFICATE = 53
    CP_RECEIVE_SERVER_KEYEXCHANGE = 54
    CP_RECEIVE_CERTIFICATE_REQUEST = 55
    
    
    CP_RECEIVE_SERVER_HELLO_DONE = 56
    CP_SERVER_HELLO_DONE_VALIDATED_CERT = 57
    
    CP_SEND_CLIENT_CERTIFICATE = 58
    CP_INIT_SEND_CLIENT_KEYEXCHANGE = 59
    CP_ENCRYPTED_CLIENT_KEYEXCHANGE = 60
    CP_GENERATED_MASTERSEC_CLIENT_KEYEXCHANGE = 61
    
    CP_INIT_SEND_CERTIFICATE_VERIFY = 62
    CP_ENCRYPTED_CERTIFICATE_VERIFY = 63
    
    CP_SEND_CIPHER_SPEC = 64  # Send the cipher spec message

    CP_INIT_CLIENT_FINISHED = 65  # start to create client finished message
    CP_HASHED_CLIENT_FINISHED = 66  # finished to hash the client finished message data
    CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED = 67  # Hash generated and sending message started
    
    CP_RECEIVE_CLIENT_CERTIFICATE = 68  # receive the client certificate
    CP_CLIENT_CERTIFICATE_VALIDATED = 69  # Finished validation of client certificate
    
    CP_RECEIVE_CLIENT_KEYEXCHANGE = 70 
    CP_DECRYPTED_CLIENT_KEYEXCHANGE = 71
    
    CP_RECEIVE_CERTIFICATE_VERIFY = 72
    CP_DECRYPTED_CERTIFICATE_VERIFY = 73    
    CP_GENERATED_MASTER_SECRET_CERT_VERIFY = 74
    
    CP_RECEIVED_CHANGE_CIPHER_SPEC = 75
    
#     CP_RECEIVED_CLIENT_FINISHED = 76
    CP_RECEIVE_CLIENT_FINISHED = 83
    CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH = 84
    CP_CLIENT_FINISHED_GENERATED_HASH_PRF = 85

    CP_RECEIVE_SERVER_FINISHED = 80
    CP_SERVER_FINISHED_HASHED_COMPARISON_HASH = 81
    CP_SERVER_FINISHED_GENERATED_HASH_PRF = 82
    
    CP_INIT_SERVER_FINISHED = 77  # start to create SERVER finished message
    CP_HASHED_SERVER_FINISHED = 78  # finished to hash the SERVER finished message data
    CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED = 79  # Hash generated and sending message started

    CP_SERVER_AUTHENTICATED = 86
    CP_CLIENT_AUTHENTICATED = 87

    CP_RECEIVE_SIMPLE_MESSAGE = 88
    
    # Checkpoints - TESLA 
    CP_INIT_EXCHANGE_FIRST_KEY_KN = 89  # Intention to send the Key K N to receiver xy
    CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN = 90  # Encryption finished for Key K_N to receiver xy
    
    CP_SETUP_INIT_CREATE_KEYS = 91  # Start the creation of keys
    CP_SETUP_FINISHED_CREATE_KEYS = 92  # Finished creating keys
    
    CP_INIT_TRANSMIT_MESSAGE = 93  # Intention to send a simple message 
    CP_MACED_TRANSMIT_MESSAGE = 94  # Finished MAC Creation of message now send it
    
    CP_RECEIVED_SIMPLE_MESSAGE = 95  # Received a simple message
    CP_BUFFERED_SIMPLE_MESSAGE = 96  # Added simple message to buffer
    CP_RETURNED_AUTHENTICATED_SIMPLE_MESSAGE = 97  # Authenticated messages are returned
    
    CP_RECEIVED_EXCHANGE_FIRST_KEY_KN = 98  # received first key message
    CP_DECRYPTED_EXCHANGE_FIRST_KEY_KN = 99  # decrypted first key message
    
    CP_INIT_CHECK_KEY_LEGID = 99.5  # start to check if key legid
    CP_CHECKED_KEY_LEGID = 100  # checked the key legidity  
    
    CP_INIT_VERIFYING_BUFFER_MESSAGE = 101  # Start validation of message in buffer
    CP_FINISHED_VERIFYING_BUFFER_MESSAGE = 102  # Done validation of message in buffer
    
    CP_SEND_SYNC_MESSAGE = 103  # send the time sync message from the ECU
    CP_SEND_SYNC_RESPONSE_MESSAGE = 104
    CP_RECEIVE_SYNC_RESPONSE_MESSAGE = 105  # End message 
    
    CP_RECEIVE_SYNC_MESSAGE = 106  # sync message was received
    
    # CAN BUS TAGS
    CB_DONE_PROCESSING_MESSAGE = 41
    CB_PROCESSING_MESSAGE = 42
    
    # Constellation Handler
    CONSELLATION_INFORMATION = 107
    ECU_ID_LIST = 108
