from config.registrator import Registrator
from config import config_io
from enums.gen_cfg_enums import IniConfig
import logging
import os

reg = Registrator()
load_config = True
create_raw_config_file = False
config_file_path = os.path.join(os.path.dirname(__file__), "data/can_ids.ini")

#===========================================================================
#     ECU Security
#===========================================================================
CAN_ECU_AUTH_ADVERTISE = 0x0001  # Highest Priority
CAN_ECU_AUTH_REG_MSG = 0x0002
CAN_ECU_AUTH_CONF_MSG = 0x0003

CAN_STR_AUTH_INIT_MSG_STR = 0x0005
CAN_STR_AUTH_GRANT_MSG = 0x0006
CAN_STR_AUTH_DENY_MSG = 0x0007

reg.reg_can_ids('LW_Authentication', 'CAN_ECU_AUTH_ADVERTISE', 'DEFAULT', 0x0001)
reg.reg_can_ids('LW_Authentication', 'CAN_ECU_AUTH_REG_MSG', 'DEFAULT', 0x0002)
reg.reg_can_ids('LW_Authentication', 'CAN_ECU_AUTH_CONF_MSG', 'DEFAULT', 0x0003)
reg.reg_can_ids('LW_Authentication', 'CAN_STR_AUTH_INIT_MSG_STR', 'DEFAULT', 0x0005)
reg.reg_can_ids('LW_Authentication', 'CAN_STR_AUTH_GRANT_MSG', 'DEFAULT', 0x0006)
reg.reg_can_ids('LW_Authentication', 'CAN_STR_AUTH_DENY_MSG', 'DEFAULT', 0x0007)

#===============================================================================
#     TESLA
#===============================================================================
CAN_TESLA_TIME_SYNC = 1
CAN_TESLA_TIME_SYNC_RESPONSE = 2
CAN_TESLA_KEY_EXCHANGE = 3

TESLA_MESSAGES = [CAN_TESLA_TIME_SYNC, CAN_TESLA_TIME_SYNC_RESPONSE, CAN_TESLA_KEY_EXCHANGE]

#===============================================================================
#     TLS
#===============================================================================
CAN_TLS_HELLO_REQUEST = 1
CAN_TLS_CLIENT_HELLO = 2
CAN_TLS_SERVER_HELLO = 3
CAN_TLS_SERVER_CERTIFICATE = 4
CAN_TLS_CERTIFICATE = 5
CAN_TLS_SERVER_KEY_EXCHANGE = 6
CAN_TLS_CERTIFICATE_REQUEST = 7
CAN_TLS_SERVER_HELLO_DONE = 8
CAN_TLS_CLIENT_KEY_EXCHANGE = 9
CAN_TLS_CERTIFICATE_VERIFY = 10
CAN_TLS_FINISHED = 12
CAN_TLS_CHANGE_CIPHER_SPEC = 11

TLS_MESSAGES = [ CAN_TLS_HELLO_REQUEST, CAN_TLS_CLIENT_HELLO, CAN_TLS_SERVER_HELLO, CAN_TLS_SERVER_CERTIFICATE, \
                CAN_TLS_CERTIFICATE, CAN_TLS_SERVER_KEY_EXCHANGE, CAN_TLS_CERTIFICATE_REQUEST, CAN_TLS_SERVER_HELLO_DONE, \
                CAN_TLS_CLIENT_KEY_EXCHANGE, CAN_TLS_CERTIFICATE_VERIFY, CAN_TLS_FINISHED, CAN_TLS_CHANGE_CIPHER_SPEC ]

reg.reg_can_ids('TLS', 'CAN_TLS_HELLO_REQUEST', 'DEFAULT', 1)
reg.reg_can_ids('TLS', 'CAN_TLS_CLIENT_HELLO', 'DEFAULT', 2)
reg.reg_can_ids('TLS', 'CAN_TLS_SERVER_HELLO', 'DEFAULT', 3)
reg.reg_can_ids('TLS', 'CAN_TLS_SERVER_CERTIFICATE', 'DEFAULT', 4)
reg.reg_can_ids('TLS', 'CAN_TLS_CERTIFICATE', 'DEFAULT', 5)
reg.reg_can_ids('TLS', 'CAN_TLS_SERVER_KEY_EXCHANGE', 'DEFAULT', 6)
reg.reg_can_ids('TLS', 'CAN_TLS_CERTIFICATE_REQUEST', 'DEFAULT', 7)
reg.reg_can_ids('TLS', 'CAN_TLS_SERVER_HELLO_DONE', 'DEFAULT', 8)
reg.reg_can_ids('TLS', 'CAN_TLS_CERTIFICATE_VERIFY', 'DEFAULT', 10)
reg.reg_can_ids('TLS', 'CAN_TLS_CLIENT_KEY_EXCHANGE', 'DEFAULT', 9)
reg.reg_can_ids('TLS', 'CAN_TLS_FINISHED', 'DEFAULT', 12)
reg.reg_can_ids('TLS', 'CAN_TLS_CHANGE_CIPHER_SPEC', 'DEFAULT', 11)

#===========================================================================
#     Battery Management
#===========================================================================
CAN_SOC_BROADCAST = 0x0008  # ('TARGET':'BROADCAST', 'ORIGIN':, 'soc' :)
CAN_VOLTAGE_BROADCAST = 0x0009  # ('TARGET':'BROADCAST', 'ORIGIN':, 'voltage' :)
CAN_BLOCK_REQUEST = 0x0010  # ('TARGET':'BROADCAST', 'ORIGIN':, 'SENDER_ID':, 'RECEIVER_ID':)
CAN_UNBLOCK_REQUEST = 0x0011  # ('TARGET':'BROADCAST', 'ORIGIN':, 'SENDER_ID':, 'RECEIVER_ID':)

CAN_SEND_REQUEST = 0x0012  # ('TARGET':, 'ORIGIN':)
CAN_SEND_ACKNOWLEDGE = 0x0013  # ('TARGET':, 'ORIGIN':, 'transferTime':, 'transferRate')

CAN_RECEIVE_REQUEST = 0x0014  # ('TARGET':, 'ORIGIN':)
CAN_RECEIVE_ACKNOWLEDGE = 0x0015  # ('TARGET':, 'ORIGIN':, 'transferTime':, 'transferRate')

CAN_STATUS_RESPONSE = 0x0020  # ('TARGET':, 'ORIGIN':, 'STATUS')

CAN_BALANCE_CONTROL = 0x00A0
CAN_SUPPLY_LOAD_MODE = 0x00A1

CAN_TEST_MSG = 25
CAN_TEST_MSG_2 = 27
CAN_TEST_MSG_3 = 29

reg.reg_can_ids('BATTERY', 'CAN_SOC_BROADCAST', 'DEFAULT', 0x0008)
reg.reg_can_ids('BATTERY', 'CAN_VOLTAGE_BROADCAST', 'DEFAULT', 0x0009)
reg.reg_can_ids('BATTERY', 'CAN_BLOCK_REQUEST', 'DEFAULT', 0x0010)
reg.reg_can_ids('BATTERY', 'CAN_UNBLOCK_REQUEST', 'DEFAULT', 0x0011)
reg.reg_can_ids('BATTERY', 'CAN_SEND_REQUEST', 'DEFAULT', 0x0012)
reg.reg_can_ids('BATTERY', 'CAN_SEND_ACKNOWLEDGE', 'DEFAULT', 0x0013)
reg.reg_can_ids('BATTERY', 'CAN_RECEIVE_REQUEST', 'DEFAULT', 0x0014)
reg.reg_can_ids('BATTERY', 'CAN_RECEIVE_ACKNOWLEDGE', 'DEFAULT', 0x0015)
reg.reg_can_ids('BATTERY', 'CAN_STATUS_RESPONSE', 'DEFAULT', 0x0020)
reg.reg_can_ids('BATTERY', 'CAN_BALANCE_CONTROL', 'DEFAULT', 0x00A0)
reg.reg_can_ids('BATTERY', 'CAN_SUPPLY_LOAD_MODE', 'DEFAULT', 0x00A1)
reg.reg_can_ids('TEST', 'CAN_TEST_MSG', 'DEFAULT', 0x0AAA)
reg.reg_can_ids('TEST', 'CAN_TEST_MSG_2', 'DEFAULT', 0x0ABC)
reg.reg_can_ids('TEST', 'CAN_TEST_MSG_3', 'DEFAULT', 0x0ABB)

#===============================================================================
#    Collection
#===============================================================================
ECU_AUTH_MESSAGES = [CAN_ECU_AUTH_ADVERTISE, CAN_ECU_AUTH_REG_MSG, \
                          CAN_ECU_AUTH_CONF_MSG]  # list of messages that are meant for the authentication and authorization
STREAM_AUTH_MESSAGES = [CAN_STR_AUTH_INIT_MSG_STR,
                             CAN_STR_AUTH_GRANT_MSG, CAN_STR_AUTH_DENY_MSG]
AUTH_MESSAGES = ECU_AUTH_MESSAGES + STREAM_AUTH_MESSAGES

#===============================================================================
#        Calculations
#===============================================================================

# Adds the created variables to the registration object
if create_raw_config_file:
    cfg = config_io.ConfigIO()
    cfg.generate_raw_cfg(reg, config_file_path, IniConfig.CAN_CFG)

logging.debug("\n\n--------------------------------------------------------- \nPROJECT SETTINGS\n ")

if load_config:
    cfg = config_io.ConfigIO()
    out = cfg.load_cfg(reg, config_file_path, IniConfig.PROJECT)
    for el in out:      
        if el == 'SSMA_STREAM_MIN_INTERVAL':
            a = 0
        exec_str = el[0] + " = el[1]"
        exec(exec_str)
        
        #===============================================================================
        #     DEBUG OUTPUT
        #===============================================================================
        logging.debug("%s = %s" % (el[0], el[1]))
    

logging.debug("\nProject Ende\n---------------------------------------------------------\n\n\n")
