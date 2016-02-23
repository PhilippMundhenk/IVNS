log_dict = {}


'''===============================================================================
    Security Module: StdSecurityModuleAppLayer
==============================================================================='''
import logging

log_dict[0] = ["\n----------------------------------------------------- \n\tStarting ECU Authentication Process %s \n----------------------------------------------------- ", False, logging.INFO]
log_dict[1] = ["\n\tTime: %s\n%s: Sending msg_id: %s and data:  Advertisement Message ", False, logging.INFO]
log_dict[2] = ["\n------> Timeout:\n------> Variable: %s\n------> Class: %s\n------> Duration: %s\n", False, logging.DEBUG]
log_dict[3] = ["%s Decrypting registration message at %s ", False, logging.INFO]
log_dict[4] = ["%s Decrypting registration message 2nd part at %s ", False, logging.INFO]
log_dict[5] = ["\nTime: %s\n%s: Received Registration message", False, logging.INFO]
log_dict[6] = ["\t%s Successfully decrypted:  %s \nStore symmetric key:  %s ", False, logging.INFO]
log_dict[7] = ["\nTime: %s\n%s Sending Confirmation message to %s", False, logging.INFO]
log_dict[8] = ["%s: Received registration message from %s. Validity: %s", False, logging.INFO]

log_dict[9] = ["\nTime: %s\n%s: Received request message %s", False, logging.INFO]
log_dict[10] = ["\tTime: %s \n%s: No allowed receivers found for this stream", False, logging.INFO]
log_dict[11] = ["\tCould not decrypt message", False, logging.INFO]
log_dict[12] = ["\t%s: Message successfully decrypted", False, logging.INFO]
log_dict[13] = ["\tInvalid timestamp", False, logging.INFO]
log_dict[14] = ["%s: Found allowed receivers %s\nStream ID: %s", False, logging.INFO]
log_dict[15] = ["Error: Cannot send grant message to receiving ECU with ID '%s', no ecu key available", False, logging.INFO]
log_dict[16] = ["\n%s: Sending grant message with key %s to receiver: %s", False, logging.INFO]
log_dict[17] = ["\n%s: Stream %s was granted already. This request will be discarded", False, logging.INFO]


'''===============================================================================
    ECU: SecureCommModule
==============================================================================='''
log_dict[100] = ["\n\tIntention to send\n\tTime: %s\n\tECU ID: %s \n\tmessage_id: %s\n\tmessage: %s \n", True, logging.INFO]
log_dict[101] = ["\tStream %s not authorized! Initializing stream authorization", False, logging.INFO]
log_dict[102] = ["\n\tTime: %s\n\tECU ID: %s \n\tStream %s authorized and Sending!", False, logging.INFO]
log_dict[103] = ["\tECU ID %s: Stream %s, Dont send Message", False, logging.INFO]
log_dict[104] = ["\tECU ID %s: Stream %s, Sending Message", False, logging.INFO]
log_dict[105] = ["\tECU ID %s: Stream %s, Dont send Message, TIMEOUT", False, logging.INFO]
log_dict[106] = ["\tECU ID %s: Stream %s STREAM AUTHORIZATION TIMED OUT, Message discarded due to missing permission", False, logging.INFO]
log_dict[107] = ["\tstream could not be initialized! No confirmation message received", False, logging.INFO]
log_dict[108] = ["\tECU ID %s: Stream %s, Waiting for granting", False, logging.INFO]
log_dict[109] = ["\tECU ID %s: Stream %s, could not decrypt it no valid session key", False, logging.INFO]
log_dict[110] = ["\tECU ID %s: Stream %s not authorized, no session key available", False, logging.INFO]
log_dict[111] = ["\tECU ID %s: Stream %s not authorized, key only valid till %s", False, logging.INFO]
log_dict[112] = ["\tECU ID %s: Stream %s authorized!", False, logging.INFO]
log_dict[113] = ["\nECU ID %s: \nStream %s, creating/sending Request Message\n", False, logging.INFO]
log_dict[114] = ["\tTime: %s\n\tECU %s: ERROR WRONG NONCE ", False, logging.INFO]
log_dict[115] = ["\tECU ID %s: Stream %s, was denied", False, logging.INFO]
log_dict[116] = ["\tECU ID %s: Stream %s, received Grant Message", False, logging.INFO]
log_dict[117] = ["\tTime: %s\n\tECU %s: ERROR Timestamp to old: %s ", False, logging.INFO]
log_dict[118] = ["\tTime: %s\n\tECU %s: ERROR WRONG NONCE ", False, logging.INFO]
log_dict[119] = ["\nTime: %s \nECU %s: Received a SEC MODULE ADVERTISEMENT", False, logging.INFO]
log_dict[120] = ["\nECU %s: Verifying received Certificate, Result Validation: %s", False, logging.INFO]
log_dict[121] = ["\tECU %s: Responding with registration message %s", False, logging.INFO]
log_dict[122] = ["\n---------------------------------------------------------------------- \n\tTime: %s\n\tECU %s: Received a Confirmation: Successfully Authenticated \n---------------------------------------------------------------------- ", False, logging.INFO]
log_dict[123] = ["\n---------------------------------------------------------------------- \n\tTime: %s\n\tECU %s: Received a Confirmation: ERROR TIMESTAMP \n---------------------------------------------------------------------- ", False, logging.INFO]
log_dict[124] = ["\n---------------------------------------------------------------------- \n\tTime: %s\n\tECU %s: Received a Confirmation: ERROR WRONG NONCE \n---------------------------------------------------------------------- ", False, logging.INFO]
log_dict[125] = ["ECU %s:\nNo confirmation message received! Do not send the message!", False, logging.INFO]

# Steps and Sizes
log_dict[126] = ["\nTime: %s\nECU_ID: %s \nStep: Create Request Message\nClear text: %s \nSize: %s", False, logging.INFO]
log_dict[127] = ["\nTime: %s\nECU_ID: %s \nStep: Create Request Message\nCipher text: %s \nEncrypted Size (sending size): %s ", False, logging.INFO]

log_dict[128] = ["\nTime: %s\nECU_ID: %s \nStep: Valid Streamed Message\nMessage ID %s\nClear text: %s \nSize: %s", False, logging.INFO]
log_dict[129] = ["\nTime: %s\nECU_ID: %s \nStep: Valid Streamed Message\nMessage ID %s\nCipher text: %s \nEncrypted Size (sending size): %s ", False, logging.INFO]

log_dict[130] = ["\nTime: %s\nECU_ID: %s \nStep: Grant Message Received\nMessage ID %s\nCipher text: %s \nSize: %s", False, logging.INFO]
log_dict[131] = ["\nTime: %s\nECU_ID: %s \nStep: Grant Message Received\nMessage ID %s\nClear text: %s \nSize: %s", False, logging.INFO]

log_dict[132] = ["\nTime: %s\nECU_ID: %s \nStep: Deny Message Received\nMessage ID %s\nCipher text: %s \nSize: %s", False, logging.INFO]
log_dict[133] = ["\nTime: %s\nECU_ID: %s \nStep: Deny Message Received\nMessage ID %s\nClear text: %s \nSize: %s", False, logging.INFO]
log_dict[134] = ["\nTime: %s\nECU_ID: %s \nStep: Receive Deny Message\nStream: %s", False, logging.INFO]
log_dict[135] = ["\nTime: %s\nECU_ID: %s \nStep: Receive Grant Message\nStream: %s", False, logging.INFO]

log_dict[136] = ["\nTime: %s\nECU_ID: %s \nStep: ECU Advertisent received \nCertificate: %s \nCertificate Signed Size: %s", False, logging.INFO]
log_dict[137] = ["\nTime: %s\nECU_ID: %s \nStep: Create Registration Message", False, logging.INFO]

log_dict[138] = ["\nTime: %s\nECU_ID: %s \nStep: Create Registration Message\nSubstep: Generate Symmetric Key", False, logging.INFO]
log_dict[139] = ["\nTime: %s\nECU_ID: %s \nStep: Create Registration Message \nInner Part Clear: %s \nInner Part Clear Size: %s", False, logging.INFO]
log_dict[140] = ["\nTime: %s\nECU_ID: %s \nStep: Create Registration Message \nHash Inner Part Clear: %s \nInner Part Clear Size: %s", False, logging.INFO]
log_dict[141] = ["\nTime: %s\nECU_ID: %s \nStep: Create Registration Message \nHash to Encrypt(outter): %s \nSize of hash to Encrypt: %s", False, logging.INFO]
log_dict[142] = ["\nTime: %s\nECU_ID: %s \nStep: Send Registration Message \nMessage to send: %s \nSize Sending Message: %s (inner encrypted) + %s (signed hash) + %s (ecu cert) = %s", False, logging.INFO]
log_dict[143] = ["\nTime: %s\nECU_ID: %s \nStep: Send Registration Message \nMessage to send: %s \nSize Sending Message: %s", False, logging.INFO]

log_dict[144] = ["\nTime: %s\nECU_ID: %s \nStep: Receive Confirmation \nCipher Message: %s \nCipher Size: %s", False, logging.INFO]
log_dict[145] = ["\nTime: %s\nECU_ID: %s \nStep: Receive Confirmation \nClear Message: %s \nClear Size: %s", False, logging.INFO]



'''===============================================================================
    api_core.py
==============================================================================='''

log_dict[200] = ["\nAdd new ECU\nenvironment: \t%s \ntype: \t\t'%s' \nId: \t\t%s", True, logging.DEBUG]
log_dict[201] = ["\nAdd new Bus \nenvironment: \t%s \ntype: \t\t'%s' \nId: \t\t%s", True, logging.DEBUG]
log_dict[202] = ["Setup new environment: \t\t%s", True, logging.DEBUG]
log_dict[203] = ["\nConnect ECU \t'%s' \nto Bus \t\t'%s'  ", True, logging.DEBUG]

log_dict[204] = ["\n------------ Component Settings ------------'  ", True, logging.DEBUG]
log_dict[205] = ["\n------------ Component Settings END ------------'  ", True, logging.DEBUG]
log_dict[206] = ["\n__________________________________________________________________________\n\t\tComponent %s:\n__________________________________________________________________________", True, logging.DEBUG]
log_dict[207] = ["%s = %s", True, logging.DEBUG]
log_dict[208] = ["%s: Unable to set variable %s", True, logging.DEBUG]
log_dict[209] = ["%s: No timing settings found. Using default settings", True, logging.DEBUG]

'''===============================================================================
    StdCANBus
==============================================================================='''
log_dict[300] = ["\n\tTime: %s\n\tSender: %s\n\tMessage Size Data Field [Byte]: %s \n\tMessage Size (interpreted by BUS) [Bit]: %s \n\tBUS %s: Sending message %s and it takes %s seconds" , False, logging.INFO]

'''===============================================================================
    SimpleApplicationLayer
==============================================================================='''
log_dict[400] = ["\n\tTime: %s \nECU_ID %s: Received a message %s", False, logging.INFO]

'''===============================================================================
    RegularApplicationLayer
==============================================================================='''
log_dict[500] = ["\n\tTime: %s \nECU_ID %s: Received a message %s", False, logging.INFO]
log_dict[501] = ["\n\tTime: %s\nECU_ID %s: Sending msg_id: %s and data:  %s ", False, logging.INFO]

'''===============================================================================
    SecureECU, StdSecurECUTimingFunctions
==============================================================================='''
log_dict[600] = ['No valid certificate defined for %s ', False, logging.INFO]

log_dict[601] = ['""""""Verify operation c_t_adv_msg_secmodcert_enc with algorithm %s and keylength %s.\nData to encrypt: %s\nCA Length: %s', False, logging.INFO]
log_dict[602] = ['Duration: %s\n', False, logging.INFO] 
log_dict[603] = ['\n***************************************> No value found for %s <***************************************', False, logging.INFO] 

log_dict[604] = ['""""""Private Encrypt(= Sign) c_t_reg_msg_inner_enc with algorithm %s and keylength %s.\nData to encrypt: %s', False, logging.INFO] 
log_dict[605] = ['""""""Hash t_reg_msg_hash with algorithm %s \nData to hash: %s', False, logging.INFO] 
log_dict[606] = ['""""""Public Encrypt t_reg_msg_outter_enc with algorithm %s and keylength %s.\nData to encrypt: %s', False, logging.INFO] 
log_dict[607] = ['""""""Symmetric Decrypt %s with algorithm %s and keylength %s.\nData to encrypt: %s\n', False, logging.INFO] 
log_dict[608] = ['""""""Symmetric Encrypt t_req_msg_stream_enc with algorithm %s and keylength %s.\nData to encrypt: %s', False, logging.INFO] 
log_dict[610] = ['""""""Symmetric Decrypt %s with algorithm %s and keylength %s.\nData to decrypt: %s', False, logging.INFO] 

'''===============================================================================
    SecLwAuthSecurityModule, StdSecurLwSecModTimingFunctions (602,603)
==============================================================================='''
log_dict[700] = ['\n""""""\nVerify operation c_t_ecu_auth_reg_msg_validate_cert with algorithm %s and keylength %s.\nData to encrypt: %s\nCA Length: %s\n', False, logging.INFO] 
log_dict[701] = ['\n""""""\nPublic Decrypting t_ecu_auth_reg_msg_inner_dec with algorithm %s and keylength %s.\nData to decrypt: %s\n', False, logging.INFO] 
log_dict[702] = ['\n""""""\nPublic Decrypting (= Verify) t_ecu_auth_reg_msg_outter_dec with algorithm %s and keylength %s.\nData to decrypt: %s\n', False, logging.INFO] 
log_dict[703] = ['\n""""""\nSymmetric Encryption t_ecu_auth_conf_msg_enc with algorithm %s and keylength %s.\nData to encrypt: %s\n', False, logging.INFO] 
log_dict[704] = ['\n""""""\nSymmetric Decryption t_str_auth_decr_req_msg with algorithm %s and keylength %s.\nData to decrypt: %s\n', False, logging.INFO] 
log_dict[705] = ['\n""""""\nSymmetric Encryption t_str_auth_decr_req_msg with algorithm %s and keylength %s.\nData to encrypt: %s\n', False, logging.INFO] 
log_dict[706] = ['\n""""""\nSymmetric Encryption t_str_auth_enc_grant_msg with algorithm %s and keylength %s.\nData to encrypt: %s\n', False, logging.INFO] 
log_dict[707] = ['\n""""""\nSymmetric Keygen t_str_auth_keygen_grant_msg with algorithm %s and keylength %s.\n', False, logging.INFO]
        

'''===============================================================================
    Base Components
==============================================================================='''
# StdTransceiver
log_dict[800] = ["\tERROR RECEIVE BUFFER OVERFLOW: Cannot receive message, its lost", True, logging.INFO]

# StdDatalinkLayer
log_dict[801] = ["\tERROR TRANSMIT BUFFER OVERFLOW: Cannot transmit message, its lost ", True, logging.INFO]

# FakeSegmentTransportLayer
log_dict[802] = ["\tTransport Layer: Receiving %s ", False, logging.INFO]

# encryption_tools
log_dict[803] = ["\tTime: %s\nUnable to encrypt message, key not valid anymore, only till %s ", False, logging.INFO]
log_dict[804] = ["\tInvalid certificate of %s ", False, logging.INFO]
log_dict[805] = ["\tCould not find corresponding Size with EncyrptionSize(). Used sending size! ", True, logging.WARN]


'''===============================================================================
    SecureApplicationLayer
==============================================================================='''
log_dict[900] = ["\n\tTime: %s \nECU_ID %s: Received a message %s", False, logging.INFO]
log_dict[901] = ["\n\tTime: %s\nECU_ID %s: Sending msg_id: %s and data:  %s ", False, logging.INFO]

log_dict[902] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Receive Registration \nCipher Message: %s \nCipher Size: %s", False, logging.INFO]
log_dict[903] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Receive Registration \nFirst Cipher Message: %s \nCipher Size: %s", False, logging.INFO]
log_dict[904] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Receive Registration \nFirst Clear Message: %s \nClear Size: %s", False, logging.INFO]
log_dict[905] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Receive Registration \nSecond Cipher Message: %s \nCipher Size: %s", False, logging.INFO]
log_dict[906] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Receive Registration \nSecond Clear Message: %s \nClear Hash Size: %s", False, logging.INFO]
log_dict[907] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Receive Registration \nCertificate: %s \nUnsigned Size: %s\nSigned Size: %s", False, logging.INFO]
log_dict[908] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Receive Registration (compare) \nCreate Hash from: %s \nSize to Hash: %s", False, logging.INFO]

log_dict[909] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Receive Stream Request\nRequesting ECU: %s\nStream ID: %s \nCipher Request Message: %s \nCipher Size: %s", False, logging.INFO]
log_dict[914] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Receive Stream Request\nRequesting ECU: %s\nStream ID: %s \nClear Request Message: %s \nClear Size: %s", False, logging.INFO]

log_dict[910] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Create Deny Message\nRequesting ECU: %s\nStream ID: %s \nClear Deny Message: %s \nClear Size: %s", False, logging.INFO]
log_dict[911] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Send Deny Message\nTarget ECU: %s\nStream ID: %s \nCipher Deny Message: %s \nSending/Cipher Size: %s", False, logging.INFO]
log_dict[912] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Create Grant Message\nTarget ECU: %s\nStream ID: %s \nClear Grant Message: %s \nClear Size: %s", False, logging.INFO]
log_dict[913] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Send Grant Message\nTarget ECU: %s\nStream ID: %s \nCipher Grant Message: %s \nSending/Cipher Size: %s", False, logging.INFO]

log_dict[915] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Create Confirmation Message\nTarget ECU: %s\nClear Conf. Message: %s \nClear Size: %s", False, logging.INFO]
log_dict[916] = ["\nTime: %s\nSEC_MOD_ID: %s \nStep: Send Confirmation Message\nTarget ECU: %s\nCipher Conf. Message: %s \nCipher Size: %s", False, logging.INFO]
log_dict[917] = ["\nTime: %s\nSEC_MOD_ID: %s \nStream: %s\n Send Deny Message to Target ECU: %s", False, logging.INFO]


#===============================================================================
#     OPTIONS
#===============================================================================
# Clear:
for kk in log_dict:
    log_dict[kk][1] = False

log_dict[17][1] = True
log_dict[107][1] = False

#===============================================================================
#     ECU SIDE OF LW Authentication
#===============================================================================
# message flows
# log_dict[100][1] = True
# log_dict[101][1] = True
# log_dict[102][1] = True


# Simple message
log_dict[100][1] = True

# Show authorization steps 
log_dict[113][1] = True  # create request message
log_dict[134][1] = True  # receive deny message
log_dict[135][1] = True  # receive grant message
#   
# # # Show authentication steps
log_dict[119][1] = True  # receive sec module advertisement
log_dict[120][1] = True  # sec module advertisement validation result
log_dict[137][1] = True  # create/send registration message
log_dict[122][1] = True  # receive confirmation message

#===============================================================================
# Stream Authorization - message content / sizes of messages
#===============================================================================
# log_dict[126][1] = True  # clear request message
# log_dict[127][1] = True  # encrypted request message
# log_dict[128][1] = True  # clear valid stream message
# log_dict[129][1] = True  # cipher valid stream message
# log_dict[130][1] = True  # cipher Grant message
# log_dict[131][1] = True  # clear Grant message
# log_dict[132][1] = True  # cipher Deny message
# log_dict[133][1] = True  # clear Deny message

#===============================================================================
# ECU Authentication - message content / sizes of messages
#===============================================================================
# log_dict[136][1] = True  # clear ecu advertisement
#    
# log_dict[138][1] = True  # create reg. msg. symmetric ecu key
# log_dict[139][1] = True  # create reg. msg. inner encryption
# log_dict[140][1] = True  # create reg. msg. hash inner
# log_dict[141][1] = True  # create reg. msg. encrypt inner hash 
# log_dict[142][1] = True  # create reg. msg. sending size AND
# log_dict[143][1] = True  # create reg. msg. sending size
#    
# log_dict[144][1] = True  # cipher confirmation msg received
# log_dict[145][1] = True  # clear confirmation msg received

#===============================================================================
# Encryption times and algorithms used 
#===============================================================================
# log_dict[600][1] = True
# log_dict[601][1] = True
# log_dict[602][1] = True
# log_dict[603][1] = True
# log_dict[604][1] = True
# log_dict[605][1] = True
# log_dict[606][1] = True
# log_dict[607][1] = True
# log_dict[608][1] = True
# log_dict[610][1] = True




#===============================================================================
#     SECURITY MODULE SIDE OF LW Authentication
#===============================================================================
# Show authentication steps
log_dict[0][1] = True  # send ecu advertisement
log_dict[5][1] = True  # received registration message
log_dict[7][1] = True  # Send confirmation message
 
# Show authorization steps
log_dict[9][1] = True  # received request message
log_dict[10][1] = True  # no allowed receiverd
log_dict[14][1] = True  # allowed receiverd
log_dict[15][1] = True  # no ecu key found
log_dict[16][1] = True  # send grant message
log_dict[917][1] = True  # send deny message

#===============================================================================
# ECU Authentication - message content / sizes of messages
#===============================================================================
# log_dict[902][1] = True  # cipher reg Message received
# log_dict[903][1] = True  # cipher reg Message FIRST Part
# log_dict[904][1] = True  # clear  reg Message FIRST Part
# log_dict[905][1] = True  # cipher reg Message SECOND Part
# log_dict[906][1] = True  # clear  reg Message SECOND Part
# log_dict[907][1] = True  # check  reg Message CERTIFICATE
# log_dict[908][1] = True  # comp.  reg Message Hashes
#  
# log_dict[915][1] = True  # clear Confirmation message
# log_dict[916][1] = True  # cipher Confirmation Message

#===============================================================================
# Stream Authorization - message content / sizes of messages
#===============================================================================
# log_dict[909][1] = True
# log_dict[910][1] = True
# log_dict[911][1] = True
# log_dict[912][1] = True
# log_dict[913][1] = True
# log_dict[914][1] = True


#===============================================================================
# Encryption times and algorithms used 
#===============================================================================
# log_dict[700][1] = True
# log_dict[701][1] = True
# log_dict[702][1] = True
# log_dict[703][1] = True
# log_dict[704][1] = True
# log_dict[705][1] = True
# log_dict[706][1] = True
# log_dict[707][1] = True

