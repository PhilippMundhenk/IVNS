
from io_processing.result_interpreter.abst_result_interpreter import AbstractInterpreter, \
    InterpreterOptions
from io_processing.surveillance_handler import MonitorTags, \
    EventlineHandler
import csv
from io_processing.result_interpreter.checkpoint_interpreter import CPCategory

class EventlineInterpreter(AbstractInterpreter):
    
    def __init__(self, export_options=False, file_path=False, ignore=False): 
        AbstractInterpreter.__init__(self, export_options, file_path)
        if ignore: return
        
        # CSV Output
        self._file_path = file_path
        self.core = CheckpointInterpreterCore()      
        self.core.init_csv(self._file_path)
        
    
    def interprete_data(self, monitor_inputs):
        ''' is invoked in certain time 
            intervals by the monitor
            
            all informations associated with the ECU are gathered 
            in CheckpointCollections      
            
            receives a result table in instead of a tuple list      
        '''
        
        if InterpreterOptions.CONNECTION in self.export_options:
            self._export_connection(monitor_inputs)
    
        # write to csv on the fly
        if InterpreterOptions.CSV_FILE in self.export_options:
            try:
                for monitor_input in monitor_inputs:
                    if not isinstance(monitor_input, (list, tuple)): continue
                    self.core.export_csv_on_fly(monitor_input[0], monitor_input[1], monitor_input[2], "", monitor_input[3], monitor_input[4], monitor_input[5], monitor_input[6], monitor_input[7], monitor_input[8])
            except:
                pass

    def get_handler(self):
        ''' 
            returns the handler classes that will send their
            data to this interpreter
        '''
        return [EventlineHandler]
    
    
class CheckpointInterpreterCore(object):
    
    def __init__(self):
      
        self._category_dict = self._get_categories()
        self._already = []
        self._csv_path = ""

    def init_csv(self, filepath):        
        try:
#             idx = filepath[::-1].find('.')
#             filepath = filepath[:(-idx - 1)] + "_run" + filepath[(-idx - 1):]
            self.csv_writer = csv.writer(open(filepath, 'w'), delimiter=';')
            el = ["Time", "Component ID", "Description", "Monitor Tag", "Processed Message", "Message Size", "Stream ID", "Category", "Message Identifier"]
            self.csv_writer.writerow(el)
        except:
            pass

    def cp_string(self, mon_tag, asc_comp_id, stream_id, message):
        
        # TESLA:
        if mon_tag == MonitorTags.CP_INIT_EXCHANGE_FIRST_KEY_KN:
            return "Intend exchanging key K_N with '%s' -> Start to encrypt it" % (asc_comp_id)
        
        if mon_tag == MonitorTags.CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN:
            return "Encrypted exchanging key K_N '%s', Stream: '%s' -> Sending it" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SETUP_INIT_CREATE_KEYS:
            return "Starting to create keys for all streams '%s'" % (asc_comp_id)
        
        if mon_tag == MonitorTags.CP_SETUP_FINISHED_CREATE_KEYS:
            return "Finished creating keys for all streams '%s'" % (asc_comp_id)
        
        if mon_tag == MonitorTags.CP_INIT_TRANSMIT_MESSAGE:
            return "Intend to send simple message to '%s', Stream: '%s' -> start MAC Creation" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_MACED_TRANSMIT_MESSAGE:
            return "Finished Creation of Mac, send simple message to '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVED_SIMPLE_MESSAGE:
            return "Receive simple message from '%s', Stream: '%s' -> Start Key legitimation" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_BUFFERED_SIMPLE_MESSAGE:
            return "Buffered simple message from '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RETURNED_AUTHENTICATED_SIMPLE_MESSAGE:
            return "Authenticated message (from buffer) from '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVED_EXCHANGE_FIRST_KEY_KN:
            return "Receive message with first key K_N '%s' -> Start decrypting it" % (asc_comp_id)
        
        if mon_tag == MonitorTags.CP_DECRYPTED_EXCHANGE_FIRST_KEY_KN:
            return "Decrypted message with first key K_N'%s'" % (asc_comp_id)
        
        if mon_tag == MonitorTags.CP_CHECKED_KEY_LEGID:
            return "Checked key legitimation for '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_INIT_VERIFYING_BUFFER_MESSAGE:
            return "Start Verifying  messages in buffer with current key '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_FINISHED_VERIFYING_BUFFER_MESSAGE:
            return "Finished verifying  messages in buffer with current key '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SEND_SYNC_MESSAGE:
            return "Send sync message to '%s'" % (asc_comp_id)
        
        if mon_tag == MonitorTags.CP_SEND_SYNC_RESPONSE_MESSAGE:
            return "Receive sync message and sending sync response message to '%s'" % (asc_comp_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_SYNC_RESPONSE_MESSAGE:
            return "Receive sync response message from '%s'" % (asc_comp_id)
        
        # TLS:
        if mon_tag == MonitorTags.CP_SESSION_AVAILABLE_SEND_MESSAGE:
            return "Sending simple message to '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SEND_CLIENT_HELLO:
            return "Sending ClientHello to '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_CLIENT_HELLO:
            return "Receive ClientHello from '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SEND_ALERT_NO_CIPHERSUITE:
            return "Error: Sending Alert to '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SEND_SERVER_HELLO:
            return "Sending Server Hello to '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SEND_SERVER_CERTIFICATE:
            return "Sending Server Certificate to '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SEND_SERVER_KEYEXCHANGE:
            return "Sending Server KeyExchange to '%s', Stream: '%s'" % (asc_comp_id, stream_id)

        if mon_tag == MonitorTags.CP_SEND_CERTIFICATE_REQUEST:
            return "Sending CertificateRequest to '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SEND_SERVER_HELLO_DONE:
            return "Sending ServerHelloDone to '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_SERVER_HELLO:
            return "Receive ServerHello from '%s', Stream: '%s' " % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE:
            return "Receive ServerCertificate from '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_SERVER_KEYEXCHANGE:
            return "Receive Server Keyexchange from '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_CERTIFICATE_REQUEST:
            return "Receive Certificate Request from '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_SERVER_HELLO_DONE:
            return "Receive ServerHelloDone from '%s', Stream: '%s' -> Start Certificate Validation" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SERVER_HELLO_DONE_VALIDATED_CERT:
            return "ServerHelloDone, validated Certificate of '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SEND_CLIENT_CERTIFICATE:
            return "Sending client Certificate to  '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_SIMPLE_MESSAGE:
            return "Received simple Message from  '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_INIT_SEND_CLIENT_KEYEXCHANGE:
            return "Want to send ClientKeyexchange to '%s' ->Start encrypting" % asc_comp_id
        
        if mon_tag == MonitorTags.CP_ENCRYPTED_CLIENT_KEYEXCHANGE:
            return "Encrypted  '%s', Stream %s -> Generating Mastersecret" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_GENERATED_MASTERSEC_CLIENT_KEYEXCHANGE:
            return "Generated Master secret for '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_INIT_SEND_CERTIFICATE_VERIFY:
            return "Want to send CertificateVerify '%s', Stream %s - > Start Encryption" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_ENCRYPTED_CERTIFICATE_VERIFY:
            return "CertificateVerify encrypted '%s', Stream: '%s' -> Send message" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SEND_CIPHER_SPEC:
            return "Sending ChangeCipherSpec to  '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_INIT_CLIENT_FINISHED:
            return "Want to send clientFinished to '%s', Stream: '%s' -> Hash Verification Data" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_HASHED_CLIENT_FINISHED:
            return "Finished first hashing of ClientFinished for '%s', Stream: '%s' ->Start hashing with prf" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED:
            return "Generated Hash for ClientFinished message to '%s', Stream: '%s' -> Sending Message" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE:
            return "Receive the client Certificate from '%s', Stream: '%s' -> Start verification" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_CLIENT_CERTIFICATE_VALIDATED:
            return "Finished verification of certificate from '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE:
            return "Receive clientKeyexchange from '%s', Stream: '%s' -> Start its decryption" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_DECRYPTED_CLIENT_KEYEXCHANGE:
            return "Decrypted clientKeyexchange message from '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_CERTIFICATE_VERIFY:
            return "Receive CertificateVerify from '%s', Stream: '%s' -> Decrypt it" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY:
            return "Decrypted CertificateVerify from '%s', Stream: '%s' -> Generate Mastersecret from Presecret" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_GENERATED_MASTER_SECRET_CERT_VERIFY:
            return "Generated MasterSecret for '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC:
            return "Received changeCipherSpec from '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_CLIENT_FINISHED:
            return "Received clientFinished Message '%s', Stream: '%s' -> Start Hashing" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH:
            return "Hashed ClientFinished Verification Data '%s', Stream: '%s' -> run PRF" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_CLIENT_FINISHED_GENERATED_HASH_PRF:
            return "Ran PRF for '%s', Stream: '%s' " % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_RECEIVE_SERVER_FINISHED:
            return "Received ServerFinished Message '%s', Stream: '%s' -> Start Hashing" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SERVER_FINISHED_HASHED_COMPARISON_HASH:
            return "Receiver: Hashed ServerFinished VerificationData '%s', Stream: '%s' -> run PRF" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SERVER_FINISHED_GENERATED_HASH_PRF:
            return "Receiver: Ran PRF for '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_INIT_SERVER_FINISHED:
            return "Sender: Want to send ServerFinished'%s', Stream: '%s' -> Start hashing" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_HASHED_SERVER_FINISHED:
            return "Sender: hashed ServerFinished Verification data '%s', Stream: '%s' -> run PRF" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED:
            return "Sender: Ran PRF  '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_SERVER_AUTHENTICATED:
            return "Client received Authentication granted from Server '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        if mon_tag == MonitorTags.CP_CLIENT_AUTHENTICATED:
            return "Server received Authentication granted from Client '%s', Stream: '%s'" % (asc_comp_id, stream_id)
        
        # Security Module
        if mon_tag == MonitorTags.CP_SEC_INIT_AUTHENTICATION:
            return "The Security Module initialized the ECU Authentication"
            
        if mon_tag == MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE:
            return "Received a Registration message from '%s' -> Start decryption" % asc_comp_id

        if mon_tag == MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE:
            return "Inner Part of Registration message was decrypted (Req. ECU: '%s')" % asc_comp_id

        if mon_tag == MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE:
            return "Outer Part of Registration message was decrypted (Req. ECU: '%s')" % asc_comp_id

        if mon_tag == MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE:
            return "Certificate of '%s' is validated" % asc_comp_id

        if mon_tag == MonitorTags.CP_SEC_CREATED_CMP_HASH_REG_MSG:
            return "Compare hash for the inner Reg. Message is created (Req. ECU: '%s')" % asc_comp_id

        if mon_tag == MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG:
            return "Comparison of inner Registration Message is finished (Req. ECU: '%s') -> Generate Confirmation" % asc_comp_id

        if mon_tag == MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE:
            return "Confirmation message was encrypted (Req. ECU: '%s') -> Send it to the ECU" % asc_comp_id
        
        if mon_tag == MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE:
            return "Received a Request message from '%s' (Stream ID: %s)-> Start decryption" % (asc_comp_id, "Unknown yet")

        if mon_tag == MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE:
            return "Request message was decrypted (Stream ID: %s, Req. ECU: '%s') -> On success start session key generation" % (stream_id, asc_comp_id)

        if mon_tag == MonitorTags.CP_SEC_GENERATED_SESSION_KEY:
            return "Session key was generated (Stream ID: %s, Req. ECU: '%s') -> send grant/deny message" % (stream_id, asc_comp_id)

        if mon_tag == MonitorTags.CP_SEC_ENCRYPTED_DENY_MESSAGE:
            return "Deny message was encrypted (Stream ID: %s, Target ECU: '%s')" % (stream_id, asc_comp_id)
        
        if mon_tag == MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE:
            return "Grant message was encrypted (Stream ID: %s, Target ECU: '%s')" % (stream_id, asc_comp_id)

        # ECU
        if mon_tag == MonitorTags.CP_ECU_ALREADY_AUTHENTICATED:
            return "ECU '%s' was already authenticated )" % asc_comp_id
        
        if mon_tag == MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE:
            return "Simple message was received from ECU: '%s')" % asc_comp_id

        if mon_tag == MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE:
            return "Simple message was decrypted (Stream ID: %s, Sending ECU: '%s')" % (stream_id, asc_comp_id)

        if mon_tag == MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE:
            return "Want to send Simple message -> Stream ID: %s " % stream_id
        
        if mon_tag == MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE:
            return "Encrypted Simple message -> Send it: Stream ID: %s; Content: '%s'" % (stream_id, message)

        if mon_tag == MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT:
            return "Receive a security Module Advertisement from '%s' -> Start certificate validation" % asc_comp_id

        if mon_tag == MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE:
            return "Certificate from '%s' validated" % asc_comp_id

        if mon_tag == MonitorTags.CP_ECU_START_CREATION_REG_MESSAGE:
            return "Start creation of registration message -> Generate ECU Key"

        if mon_tag == MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE:
            return "Created the symmetric ECU Key for Registration Message -> Start to encrypt inner Part" 

        if mon_tag == MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE:
            return "Encrypted the inner Registration Message -> Start Hash of inner message"

        if mon_tag == MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE:
            return "Hashed the inner Registration Message -> Start encryption of this hashed part"

        if mon_tag == MonitorTags.CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE:
            return "Encrypted the outer Registration Message (Hashed inner Part)"

        if mon_tag == MonitorTags.CP_ECU_SEND_REG_MESSAGE:
            return "Send the Registration Message to '%s'" % asc_comp_id

        if mon_tag == MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE:
            return "Receive confirmation Message from '%s' -> Start to decrypt it" % asc_comp_id

        if mon_tag == MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE:
            return "Decrypted confirmation Message from '%s' -> Successfully Authenticated" % asc_comp_id

        if mon_tag == MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE:
            return "Start creation of Request Message (Stream ID: %s)" % stream_id

        if mon_tag == MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE:
            return "Encrypted Request Message (Stream ID: %s)" % stream_id

        if mon_tag == MonitorTags.CP_ECU_RECEIVE_DENY_MESSAGE:
            return "Receive Deny Message (Stream ID: %s) -> Start to decrypt" % "Unknown"
        
        if mon_tag == MonitorTags.CP_ECU_DECRYPTED_DENY_MESSAGE:
            return "Decrypted Deny Message (Stream ID: %s)" % stream_id

        if mon_tag == MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE:
            return "Receive Grant Message (Stream ID: %s) -> Start to decrypt" % "Unknown"
        
        if mon_tag == MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE:
            return "Decrypted Grant Message (Stream ID: %s)" % stream_id
        
        return str(mon_tag)

    def export_csv_on_fly(self, time, comp_id, asc_comp_id, category, mon_tag, msg_id, message, msg_size, stream_id, uq_id):
        # Export all to the given file 
       
        el = [str(time), str(comp_id), str(self.cp_string(eval(mon_tag), asc_comp_id, stream_id, message)), mon_tag, str(message), str(msg_size), str(stream_id), str(category), str(msg_id)]
        self.csv_writer.writerow(el)

    def _category_by_tag(self, tag):
        for ky in self._category_dict:
            if tag in self._category_dict[ky]:
                return ky
        return None

    def _get_categories(self):
        
        cat = {}
        
        cat[CPCategory.ECU_AUTHENTICATION_TRANS] = [MonitorTags.CP_SEC_INIT_AUTHENTICATION, MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE, MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT, MonitorTags.CP_ECU_SEND_REG_MESSAGE, \
                                                    MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE, MonitorTags.CP_ECU_ALREADY_AUTHENTICATED]
        
        cat[CPCategory.ECU_AUTHENTICATION_ENC] = [ MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE, MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE, \
            MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE, MonitorTags.CP_SEC_CREATED_CMP_HASH_REG_MSG, \
            MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG, MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE, \
            MonitorTags.CP_ECU_START_CREATION_REG_MESSAGE, MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE, MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE, MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE, \
            MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE]
                                                    
        cat[CPCategory.STREAM_AUTHORIZATION_TRANS] = [MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE, MonitorTags.CP_ECU_RECEIVE_DENY_MESSAGE, MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE]
            
        cat[CPCategory.STREAM_AUTHORIZATION_ENC] = [MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE, \
            MonitorTags.CP_SEC_GENERATED_SESSION_KEY, MonitorTags.CP_SEC_ENCRYPTED_DENY_MESSAGE, \
            MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE, MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE, \
            MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE, MonitorTags.CP_ECU_DECRYPTED_DENY_MESSAGE, MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE]
            
        cat[CPCategory.SIMPLE_MESSAGE_TRANS] = [ MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE, MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE]
                                                                     
        cat[CPCategory.SIMPLE_MESSAGE_ENC] = [ MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE, MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE]
            
        return cat
    
