'''
This module is used to register timings

Explanation:
Information provided in this section defines the assignment of timing Variables
used in the code and their values depending on settings
Those variables can be one of the following:

    - Fixed Values:     If the user specifies a numerical value in the timings.ini file
                        then this value is used as timing value
                        
    - Symbol Value:     If an symbol (kind of enum) is defined here and then specified in 
      (simple timing)   the ini file, then the value corresponding to this symbol is used as timing value
                           
    - Function Value:   If the time is depending on input parameters that are provided during the program
      (CALC_X)          execution, then a function can be called to determine the timing value depending on 
                        the program flow

    - Database Lookup:  Certain measurements were taken which depend on certain parameters. Specifying a variable
      (DBLookup)        as DBLookup will try to find a value for this timing depending on three Facts:
                            i.   what is the ID of the Variable
                            ii.  what are the specified project settings (in project.ini)
                            iii. What is the mapping between ID and project.ini information to the DB information (timing.xml)
                            iv.  DB entry corresponding to this information
    
    - Interpolation:    Does the same as the DB Lookup with the difference that more than one value is determined and from those
      (DBInterpol)      information a value is interpolated 
    
'''
import config.project_registration as preg  # NECESSARY, needs to boot first
from config.registrator import Registrator
import config.timing_reg_formulas as formula
import sys
from config import config_io
from enums.gen_cfg_enums import IniConfig
import logging
import os

reg = Registrator()
call = formula.call

load_config = True
create_raw_config_file = False
config_file_path = os.path.join(os.path.dirname(__file__), "data/timings.ini")

#===============================================================================
#     CANGateway
#===============================================================================
# Processing Time per message
GW_TRANSITION_PROCESS = 0.00000001
reg.reg_simp_timing('StdCANBus', 'SCB_GATHER_MSGS', 'LONG', 2)

#===============================================================================
#    COMPONENTS.BUS
#    StdCANBus
#===============================================================================

# Time to gather information (!= 0)
SCB_GATHER_MSGS = 0
reg.reg_simp_timing('StdCANBus', 'SCB_GATHER_MSGS', 'LONG', 2)
reg.reg_simp_timing('StdCANBus', 'SCB_GATHER_MSGS', 'FAST', sys.float_info.min)
reg.reg_simp_timing('StdCANBus', 'SCB_GATHER_MSGS', 'DEFAULT', sys.float_info.min)
reg.reg_simp_timing('StdCANBus', 'SCB_GATHER_MSGS', 'CUSTOMIZED', 0)

# Time to grab highest priority message 
SCB_GRAB_PRIO_MSG = 0
reg.reg_simp_timing('StdCANBus', 'SCB_GRAB_PRIO_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('StdCANBus', 'SCB_GRAB_PRIO_MSG', 'CUSTOMIZED', 0)


# Transmission Times SCB_PROPAGATION_DELAY is either a function or a constant! 
# usage: time.call(time.SCB_PROPAGATION_DELAY, arg_1, arg_2,...)
SCB_PROPAGATION_DELAY = formula.calc_prop_delay  # DEFAULT 
reg.reg_simp_timing('StdCANBus', 'SCB_PROPAGATION_DELAY', 'CALC', formula.calc_prop_delay)  # means that it is calculated automatically t = s/v
reg.reg_simp_timing('StdCANBus', 'SCB_PROPAGATION_DELAY', 'DEFAULT', formula.calc_prop_delay)
reg.reg_simp_timing('StdCANBus', 'SCB_PROPAGATION_DELAY', 'CUSTOMIZED', 0)

SCB_SENDING_TIME = formula.calc_sending_time
reg.reg_simp_timing('StdCANBus', 'SCB_SENDING_TIME', 'CALC', formula.calc_sending_time)  # means that it is calculated automatically t = msg_length/datarate
reg.reg_simp_timing('StdCANBus', 'SCB_SENDING_TIME', 'DEFAULT', formula.calc_sending_time)
reg.reg_simp_timing('StdCANBus', 'SCB_SENDING_TIME', 'CUSTOMIZED', 0)

# Time it takes for the Bus to write the received message to the receiving Buffers of the ECUs
SCB_WRITE_TO_TRANSCEIVER_BUFFER = 0
reg.reg_simp_timing('StdCANBus', 'SCB_WRITE_TO_TRANSCEIVER_BUFFER', 'DEFAULT', 0)
reg.reg_simp_timing('StdCANBus', 'SCB_WRITE_TO_TRANSCEIVER_BUFFER', 'CUSTOMIZED', 0)

#===============================================================================
#    COMPONENTS.ECU.HARDWARE
#    StdTransceiver
#===============================================================================

# Time to put message on the bus (From Transceiver to Bus)
ST_PUT_ON_BUS = 0
reg.reg_simp_timing('StdTransceiver', 'ST_PUT_ON_BUS', 'DEFAULT', 0)
reg.reg_simp_timing('StdTransceiver', 'ST_PUT_ON_BUS', 'CUSTOMIZED', 0)

#===============================================================================
#    COMPONENTS.ECU.SOFTWARE
#    SegmentCommModule
#===============================================================================

# Processing time of comm_mod_when_receiving the message
SCM_RECEIVE_PROCESS = 0
reg.reg_simp_timing('SegmentCommModule', 'SCM_RECEIVE_PROCESS', 'NORMAL', 0)
reg.reg_simp_timing('SegmentCommModule', 'SCM_RECEIVE_PROCESS', 'DEFAULT', 0)
reg.reg_simp_timing('SegmentCommModule', 'SCM_RECEIVE_PROCESS', 'CUSTOMIZED', 0)

SCM_SEND_PROCESS = 0
reg.reg_simp_timing('SegmentCommModule', 'SCM_SEND_PROCESS', 'NORMAL', 0)
reg.reg_simp_timing('SegmentCommModule', 'SCM_SEND_PROCESS', 'DEFAULT', 0)
reg.reg_simp_timing('SegmentCommModule', 'SCM_SEND_PROCESS', 'CUSTOMIZED', 0)

#===============================================================================
#    COMPONENTS.ECU.SOFTWARE
#    StdCommModule
#===============================================================================

# Processing time of comm_mod when_receiving the message
STDCM_RECEIVE_PROCESS = 0
reg.reg_simp_timing('StdCommModule', 'STDCM_RECEIVE_PROCESS', 'NORMAL', 0)
reg.reg_simp_timing('StdCommModule', 'STDCM_RECEIVE_PROCESS', 'DEFAULT', 0)
reg.reg_simp_timing('StdCommModule', 'STDCM_RECEIVE_PROCESS', 'CUSTOMIZED', 0)

# Processing time of comm_mod when sending the message
STDCM_SEND_PROCESS = 0
reg.reg_simp_timing('StdCommModule', 'STDCM_SEND_PROCESS', 'DEFAULT', 0)
reg.reg_simp_timing('StdCommModule', 'STDCM_SEND_PROCESS', 'CUSTOMIZED', 0)


#===============================================================================
#    COMPONENTS.ECU.SOFTWARE
#    StdDatalinkLayer
#===============================================================================

# Time it takes to fill the receive buffer (time: From receive buffer to DLL has message)
STDDLL_RECEIVE_BUFFER = 0  
reg.reg_simp_timing('StdDatalinkLayer', 'STDDLL_RECEIVE_BUFFER', 'DEFAULT', 0)
reg.reg_simp_timing('StdDatalinkLayer', 'STDDLL_RECEIVE_BUFFER', 'CUSTOMIZED', 0)

# Time it takes to fill the transmit buffer (time: From DLL to Transmit Buffer has message)
STDDLL_TRANSMIT_BUFFER = 0
reg.reg_simp_timing('StdDatalinkLayer', 'STDDLL_TRANSMIT_BUFFER', 'DEFAULT', 0)
reg.reg_simp_timing('StdDatalinkLayer', 'STDDLL_TRANSMIT_BUFFER', 'CUSTOMIZED', 0)

# Time it takes to get the next message with highest priority
STDDLL_GET_MSG_PRIO = 0
reg.reg_simp_timing('StdDatalinkLayer', 'STDDLL_GET_MSG_PRIO', 'DEFAULT', 0)
reg.reg_simp_timing('StdDatalinkLayer', 'STDDLL_GET_MSG_PRIO', 'CUSTOMIZED', 0)

# After collision -> listen to channel -> when channel free -> wait backoff -> send msg
STDDLL_BACKOFF_AFTER_COL = formula.calc_collis_backoff  # DEFAULT 
reg.reg_simp_timing('StdDatalinkLayer', 'STDDLL_BACKOFF_AFTER_COL', 'CALC', formula.calc_collis_backoff)  # means that it is calculated automatically t = s/v
reg.reg_simp_timing('StdDatalinkLayer', 'STDDLL_BACKOFF_AFTER_COL', 'DEFAULT', 0.000001)
reg.reg_simp_timing('StdDatalinkLayer', 'STDDLL_BACKOFF_AFTER_COL', 'CUSTOMIZED', 0.000001)

#===============================================================================
#    COMPONENTS.ECU.SOFTWARE
#    StdTransportLayer
#===============================================================================

# Processing time of Transport Layer after receiving the message
STDTL_RECEIVE_PROCESS = 0 
reg.reg_simp_timing('StdTransportLayer', 'STDTL_RECEIVE_PROCESS', 'NORMAL', 0.1)
reg.reg_simp_timing('StdTransportLayer', 'STDTL_RECEIVE_PROCESS', 'DEFAULT', 0)
reg.reg_simp_timing('StdTransportLayer', 'STDTL_RECEIVE_PROCESS', 'CUSTOMIZED', 0)

# Processing time of Transport Layer when sending the message
STDTL_SEND_PROCESS = 0     
reg.reg_simp_timing('StdTransportLayer', 'STDTL_SEND_PROCESS', 'DEFAULT', 0)
reg.reg_simp_timing('StdTransportLayer', 'STDTL_SEND_PROCESS', 'CUSTOMIZED', 0)

#===============================================================================
#    COMPONENTS.ECU.SOFTWARE
#    SegmentTransportLayer
#===============================================================================

# Processing time of Transport Layer after receiving the message
SEGTL_RECEIVE_PROCESS = 0
reg.reg_simp_timing('SegmentTransportLayer', 'SEGTL_RECEIVE_PROCESS', 'CALC', formula.segtl_receive_time)
reg.reg_simp_timing('SegmentTransportLayer', 'SEGTL_RECEIVE_PROCESS', 'DEFAULT', formula.segtl_receive_time)
reg.reg_simp_timing('SegmentTransportLayer', 'SEGTL_RECEIVE_PROCESS', 'CUSTOMIZED', 0)

# Processing time of Transport Layer when sending the message
SEGTL_SEND_PROCESS = 0
reg.reg_simp_timing('SegmentTransportLayer', 'SEGTL_SEND_PROCESS', 'CALC', formula.segtl_send_time)
reg.reg_simp_timing('SegmentTransportLayer', 'SEGTL_SEND_PROCESS', 'DEFAULT', formula.segtl_send_time)
reg.reg_simp_timing('SegmentTransportLayer', 'SEGTL_SEND_PROCESS', 'CUSTOMIZED', 0)

#===============================================================================
#    COMPONENTS.ECU.SOFTWARE
#    FakeSegmentTransportLayer
#===============================================================================

# Processing time of Transport Layer after receiving the message
FSEGTL_RECEIVE_PROCESS = 0
reg.reg_simp_timing('FakeSegmentTransportLayer', 'FSEGTL_RECEIVE_PROCESS', 'CALC', formula.fake_segtl_receive_time)
reg.reg_simp_timing('FakeSegmentTransportLayer', 'FSEGTL_RECEIVE_PROCESS', 'DEFAULT', formula.fake_segtl_receive_time)
reg.reg_simp_timing('FakeSegmentTransportLayer', 'FSEGTL_RECEIVE_PROCESS', 'CUSTOMIZED', 0)

# Processing time of Transport Layer when sending the message
FSEGTL_SEND_PROCESS = 0
reg.reg_simp_timing('FakeSegmentTransportLayer', 'FSEGTL_SEND_PROCESS', 'CALC', formula.fake_segtl_send_time)
reg.reg_simp_timing('FakeSegmentTransportLayer', 'FSEGTL_SEND_PROCESS', 'DEFAULT', formula.fake_segtl_send_time)
reg.reg_simp_timing('FakeSegmentTransportLayer', 'FSEGTL_SEND_PROCESS', 'CUSTOMIZED', 0)

#===============================================================================
#    COMPONENTS.SECURITY.ECU.SOFTWARE
#    StdSecurityModuleAppLayer        -> SECURITY MODULE SIDE
#===============================================================================

    #===========================================================================
    #     ECU AUTHENTICATION
    #===========================================================================
# Processing time before sending the ECU_AUTH_ADVERTISE Message to the ECUs (so time after the interval is over till message is really sent)
SSMA_TRIGGER_AUTH_PROCESS_T = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_TRIGGER_AUTH_PROCESS_T', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_TRIGGER_AUTH_PROCESS_T', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_TRIGGER_AUTH_PROCESS_T', 'CUSTOMIZED', 0)

# Time to decrypt the outter part of received registration message
SSMA_DECR_OUTTER_REG_MSG = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_DECR_OUTTER_REG_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_DECR_OUTTER_REG_MSG', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_DECR_OUTTER_REG_MSG', 'CUSTOMIZED', 0)

# Time to decrypt the inner part of received registration message
SSMA_DECR_INNER_REG_MSG = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_DECR_INNER_REG_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_DECR_INNER_REG_MSG', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_DECR_INNER_REG_MSG', 'CUSTOMIZED', 0)

# Time it takes to validate the certificate that was sent with the registration message
SSMA_VALID_CERT_REG_MSG = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_VALID_CERT_REG_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_VALID_CERT_REG_MSG', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_VALID_CERT_REG_MSG', 'CUSTOMIZED', 0)

# Time it takes to compare create the hash that will be compared to the one in the registration message 
SSMA_CREATE_CMP_HASH_REG_MSG = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_CREATE_CMP_HASH_REG_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_CREATE_CMP_HASH_REG_MSG', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_CREATE_CMP_HASH_REG_MSG', 'CUSTOMIZED', 0)

# Time it takes to compare the hash in the registration message 
SSMA_HASH_CMPR_REG_MSG = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_HASH_CMPR_REG_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_HASH_CMPR_REG_MSG', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_HASH_CMPR_REG_MSG', 'CUSTOMIZED', 0)

# Time it takes to encrypt the confirmation message with the ECU KEY
SSMA_ENCR_CONF_MSG_ECU_KEY = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_ENCR_CONF_MSG_ECU_KEY', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_ENCR_CONF_MSG_ECU_KEY', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_ENCR_CONF_MSG_ECU_KEY', 'CUSTOMIZED', 0)



    #===========================================================================
    #     STREAM AUTHORIZATION
    #===========================================================================
# Time it takes to decrypt the Stream request message
SSMA_STREAM_REQ_INI_DECR = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_ENCR_CONF_MSG_ECU_KEY', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_ENCR_CONF_MSG_ECU_KEY', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_ENCR_CONF_MSG_ECU_KEY', 'CUSTOMIZED', 0)

# Time it takes to encrypt the Deny message after a stream request
SSMA_STREAM_ENC_DENY_MSG = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_STREAM_ENC_DENY_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_STREAM_ENC_DENY_MSG', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_STREAM_ENC_DENY_MSG', 'CUSTOMIZED', 0)

# Time it takes to encrypt the Grant message after a stream request
SSMA_STREAM_ENC_GRANT_MSG = 0
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_STREAM_ENC_GRANT_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_STREAM_ENC_GRANT_MSG', 'NORMAL', 10)
reg.reg_simp_timing('StdSecurityModuleAppLayer', 'SSMA_STREAM_ENC_GRANT_MSG', 'CUSTOMIZED', 0)

#===============================================================================
#    COMPONENTS.SECURITY.ECU.SOFTWARE
#    SecureCommModule                -> Secure ECU SIDE
#===============================================================================

    #===========================================================================
    #     ECU AUTHENTICATION
    #===========================================================================
    
# Time it takes for the ECU to verify the Certificate of the Security module
SCCM_ECU_ADV_SEC_MOD_CERT_VAL = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ADV_SEC_MOD_CERT_VAL', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ADV_SEC_MOD_CERT_VAL', 'NORMAL', 10)    
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ADV_SEC_MOD_CERT_VAL', 'CUSTOMIZED', 0)

# Time it takes for the ECU to generate a new symmetric key for the registration message
SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ENC_REG_MSG_CREATE_SYM_KEY', 'CUSTOMIZED', 0)

# Time it takes for the ECU to encrypt the inner part of the registration message
SCCM_ECU_ENC_REG_MSG_INNER = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ENC_REG_MSG_INNER', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ENC_REG_MSG_INNER', 'NORMAL', 10)  
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ENC_REG_MSG_INNER', 'CUSTOMIZED', 0)

# Time it takes to hash the part in the registration message
SCCM_ECU_HASH_REG_MSG = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_HASH_REG_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_HASH_REG_MSG', 'NORMAL', 10)  
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_HASH_REG_MSG', 'CUSTOMIZED', 0)

# Time it takes for the ECU to encrypt the outter part of the registration message
SCCM_ECU_ENC_REG_MSG_OUTTER = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ENC_REG_MSG_OUTTER', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ENC_REG_MSG_OUTTER', 'NORMAL', 10)  
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_ENC_REG_MSG_OUTTER', 'CUSTOMIZED', 0)

# Time it takes for the ECU to decrypt the confirmation message
SCCM_ECU_DEC_CONF_MSG = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_DEC_CONF_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_DEC_CONF_MSG', 'NORMAL', 10)  
reg.reg_simp_timing('SecureCommModule', 'SCCM_ECU_DEC_CONF_MSG', 'CUSTOMIZED', 0)

    #===========================================================================
    #     STREAM AUTHORIZATION
    #===========================================================================

# Time to encrypt the request message of the stream authorization
SCCM_STREAM_ENC_REQ_MSG = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_ENC_REQ_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_ENC_REQ_MSG', 'NORMAL', 10)
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_ENC_REQ_MSG', 'CUSTOMIZED', 0)

# Time to decrypt a grant message 
SCCM_STREAM_DEC_GRANT_MSG = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_DEC_GRANT_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_DEC_GRANT_MSG', 'NORMAL', 10)  
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_DEC_GRANT_MSG', 'CUSTOMIZED', 0)

SCCM_STREAM_DEC_DENY_MSG = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_DEC_DENY_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_DEC_DENY_MSG', 'NORMAL', 10)  
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_DEC_DENY_MSG', 'CUSTOMIZED', 0)

# Time to decrypt a received simple message with the session key
SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY', 'NORMAL', 10)   
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_DEC_SIMP_MSG_SESS_KEY', 'CUSTOMIZED', 0)

# Time to generate the session key
SSMA_SESS_KEYGEN_GRANT_MSG = 0
reg.reg_simp_timing('SecureCommModule', 'SSMA_SESS_KEYGEN_GRANT_MSG', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SSMA_SESS_KEYGEN_GRANT_MSG', 'NORMAL', 10)  
reg.reg_simp_timing('SecureCommModule', 'SSMA_SESS_KEYGEN_GRANT_MSG', 'CUSTOMIZED', 0)

# Time to encrypt a simple message (to sent) with the session key
SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY = 0
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY', 'DEFAULT', 0)
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY', 'NORMAL', 10)  
reg.reg_simp_timing('SecureCommModule', 'SCCM_STREAM_ENC_SIMP_MSG_SESS_KEY', 'CUSTOMIZED', 0)

#===============================================================================
#     TLS
#===============================================================================

# Record Layer timings
TLSR_COMPRESSION_TIME = 0.00011
reg.reg_simp_timing('TLS', 'TLSR_COMPRESSION_TIME', 'DEFAULT', 0.0001)

TLSR_DECOMPRESSION_TIME = 0.00011
reg.reg_simp_timing('TLS', 'TLSR_DECOMPRESSION_TIME', 'DEFAULT', 0.0001)

TLSR_MAC_BLOCKCIPHER_SEND_TIME = 0
reg.reg_proj_config('TLS', 'TLSR_MAC_BLOCKCIPHER_SEND_TIME', 'DEFAULT', 0.0001)

TLSR_MAC_BLOCKCIPHER_REC_TIME = 0
reg.reg_proj_config('TLS', 'TLSR_MAC_BLOCKCIPHER_SEND_TIME', 'DEFAULT', 0.0001)

TLSR_BLOCKCIPHER_ENC_TIME = 0
reg.reg_simp_timing('TLS', 'TLSR_BLOCKCIPHER_ENC_TIME', 'DEFAULT', 0)

TLSR_BLOCKCIPHER_DEC_TIME = 0
reg.reg_simp_timing('TLS', 'TLSR_BLOCKCIPHER_DEC_TIME', 'DEFAULT', 0)

TLSH_DEC_CERT_VERIFY_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_DEC_CERT_VERIFY_TIME', 'DEFAULT', 0)

TLSH_ENC_CERT_VERIFY_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_ENC_CERT_VERIFY_TIME', 'DEFAULT', 0)

TLSH_PRF_WORKING_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_PRF_WORKING_TIME', 'DEFAULT', 0)

TLSH_DEC_CLIENT_KEYEX_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_DEC_CLIENT_KEYEX_TIME', 'DEFAULT', 0)

TLSH_ENC_CLIENT_KEYEX_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_ENC_CLIENT_KEYEX_TIME', 'DEFAULT', 0)

TLSH_SERVER_REC_FINISHED_HASH_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_SERVER_REC_FINISHED_HASH_TIME', 'DEFAULT', 0)

TLSH_CLIENT_REC_FINISHED_HASH_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_CLIENT_REC_FINISHED_HASH_TIME', 'DEFAULT', 0)

TLSH_SERVER_SEND_FINISHED_HASH_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_SERVER_SEND_FINISHED_HASH_TIME', 'DEFAULT', 0)

TLSH_CLIENT_SEND_FINISHED_HASH_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_CLIENT_SEND_FINISHED_HASH_TIME', 'DEFAULT', 0)

TLSH_SERV_HELLO_DONE_VERIFY_CERT_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_SERV_HELLO_DONE_VERIFY_CERT_TIME', 'DEFAULT', 0)

TLSH_CERIFY_CLIENT_CERT_TIME = 0
reg.reg_simp_timing('TLS', 'TLSH_SERV_HELLO_DONE_VERIFY_CERT_TIME', 'DEFAULT', 0)

#===============================================================================
#     TESLA
#===============================================================================
# Time to generate one mac key from another
TESLA_ONE_KEY_CREATION = 0
reg.reg_simp_timing('TESLA', 'TESLA_ONE_KEY_CREATION', 'DEFAULT', 0)

# Time to generate the mac to compare it with the generated at transmit
TESLA_MAC_GEN_VERIFY_TIME_TRANSMIT = 0
reg.reg_simp_timing('TESLA', 'TESLA_MAC_GEN_VERIFY_TIME_TRANSMIT', 'DEFAULT', 0)

# Time to generate the mac from a input
TESLA_MAC_GEN_TIME_TRANSMIT = 0
reg.reg_simp_timing('TESLA', 'TESLA_MAC_GEN_TIME_TRANSMIT', 'DEFAULT', 0)

# Time to encrypt the first message publically
TESLA_KEY_EXCHANGE_ENC_TIME = 0
reg.reg_simp_timing('TESLA', 'TESLA_KEY_EXCHANGE_ENC_TIME', 'DEFAULT', 0)

# Time to decrypt the first message privately
TESLA_KEY_EXCHANGE_DEC_TIME = 0
reg.reg_simp_timing('TESLA', 'TESLA_KEY_EXCHANGE_DEC_TIME', 'DEFAULT', 0)

# Time for one PRF run to legitimate the Key
TESLA_KEY_LEGID_PRF_TIME = 0
reg.reg_simp_timing('TESLA', 'TESLA_KEY_LEGID_PRF_TIME', 'DEFAULT', 0)

#===============================================================================
#        Calculations
#===============================================================================


# Adds the created variables to the registration object

if create_raw_config_file:
    cfg = config_io.ConfigIO()
    cfg.generate_raw_cfg(reg, config_file_path, IniConfig.TIMING)

logging.debug("\n\n--------------------------------------------------------- \nTIMING SETTINGS \n")

if load_config:
    cfg = config_io.ConfigIO()
    out = cfg.load_cfg(reg, config_file_path, IniConfig.TIMING, preg.__dict__)
    for el in out:       
        exec_str = el[0] + " = el[1]"
        exec(exec_str)
        
        #===============================================================================
        #     DEBUG OUTPUT
        #===============================================================================
        logging.debug("%s = %s" % (el[0], el[1]))
    

logging.debug("\nTiming Ende\n---------------------------------------------------------\n\n\n")










