
from config.registrator import Registrator
from config import config_io
from enums.gen_cfg_enums import IniConfig
from enums.sec_cfg_enum import SymAuthMechEnum, AsymAuthMechEnum, \
    AuKeyLengthEnum, HashMechEnum, PRF
import logging
from components.base.message.impl_bus_message_can import *  # @UnusedWildImport
import os
from components.base.message.impl_bus_message_can_fd import CANFDSegMessage
import sys
from enums.tls_enums import CompressionMethod

'''
valid values for those objects are:
    constants
    list of singleton objects and functions ['singleton_class_full_qualified', 'func_to_call']
        (args are coming from call)     
'''

reg = Registrator()
load_config = True
create_raw_config_file = False
config_file_path = os.path.join(os.path.dirname(__file__), "data/project.ini")

#===============================================================================
#     DEFINITIONS
#===============================================================================    
DEF_HASH_SIZE = {HashMechEnum.SHA1 : 20, HashMechEnum.SHA256 : 32, HashMechEnum.MD5 : 16}

#===============================================================================
#     GENERAL
#===============================================================================
BUS_MSG_CLASS = CANSegMessage
reg.reg_proj_config('General', 'BUS_MSG_CLASS', 'CAN', CANSegMessage)
reg.reg_proj_config('General', 'BUS_MSG_CLASS', 'CAN_SEG', CANSegMessage)
reg.reg_proj_config('General', 'BUS_MSG_CLASS', 'CAN_FD', CANFDSegMessage)
reg.reg_proj_config('General', 'BUS_MSG_CLASS', 'CAN_FD_SEG', CANFDSegMessage)

NONCE_VALIDITY = 10
reg.reg_proj_config('General', 'NONCE_VALIDITY', 'INFINITY', sys.maxsize)

TIMESTAMP_VALIDITY = 9000  # Duration
reg.reg_proj_config('General', 'TIMESTAMP_VALIDITY', 'INFINITY', sys.maxsize)

APP_LIFETIME = 2000
reg.reg_proj_config('General', 'APP_LIFETIME', 'DEFAULT', 2000)

BUS_ECU_DATARATE = 1000000
reg.reg_proj_config('General', 'BUS_ECU_DATARATE', 'HIGH_SPEED', 1000000)
reg.reg_proj_config('General', 'BUS_ECU_DATARATE', 'LOW_SPEED', 125000)

#===============================================================================
#      CERTIFICATION
#===============================================================================
ECU_CERT_HASHING_MECH = HashMechEnum.MD5
reg.reg_proj_config('Certification', 'ECU_CERT_HASHING_MECH', 'MD5', HashMechEnum.MD5)
reg.reg_proj_config('Certification', 'ECU_CERT_HASHING_MECH', 'SHA1', HashMechEnum.SHA1)
reg.reg_proj_config('Certification', 'ECU_CERT_HASHING_MECH', 'SHA256', HashMechEnum.SHA256)

ECU_CERT_ENCRYPTION_MECH = AsymAuthMechEnum.RSA
reg.reg_proj_config('Certification', 'ECU_CERT_ENCRYPTION_MECH', 'RSA', AsymAuthMechEnum.RSA)
reg.reg_proj_config('Certification', 'ECU_CERT_ENCRYPTION_MECH', 'ECC', AsymAuthMechEnum.ECC)

ECU_CERT_ENCRYPTION_MECH_OPTION = 3
reg.reg_proj_config('Certification', 'ECU_CERT_ENCRYPTION_MECH_OPTION', 'EXP_3', 3)
reg.reg_proj_config('Certification', 'ECU_CERT_ENCRYPTION_MECH_OPTION', 'EXP_5', 5)
reg.reg_proj_config('Certification', 'ECU_CERT_ENCRYPTION_MECH_OPTION', 'EXP_17', 17)
reg.reg_proj_config('Certification', 'ECU_CERT_ENCRYPTION_MECH_OPTION', 'EXP_257', 257)
reg.reg_proj_config('Certification', 'ECU_CERT_ENCRYPTION_MECH_OPTION', 'EXP_65537', 65537)

ECU_CERT_KEYL = AuKeyLengthEnum.bit_1024
reg.reg_proj_config('Certification', 'ECU_CERT_KEYL', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('Certification', 'ECU_CERT_KEYL', 'bit_256', AuKeyLengthEnum.bit_256)
reg.reg_proj_config('Certification', 'ECU_CERT_KEYL', 'bit_384', AuKeyLengthEnum.bit_384)
reg.reg_proj_config('Certification', 'ECU_CERT_KEYL', 'bit_512', AuKeyLengthEnum.bit_512)
reg.reg_proj_config('Certification', 'ECU_CERT_KEYL', 'bit_1024', AuKeyLengthEnum.bit_1024)
reg.reg_proj_config('Certification', 'ECU_CERT_KEYL', 'bit_2048', AuKeyLengthEnum.bit_2048)

ECU_CERT_CA_LEN = 1
reg.reg_proj_config('Certification', 'ECU_CERT_CA_LEN', 'ca_1', 1)
reg.reg_proj_config('Certification', 'ECU_CERT_CA_LEN', 'ca_2', 2)
reg.reg_proj_config('Certification', 'ECU_CERT_CA_LEN', 'ca_3', 3)
reg.reg_proj_config('Certification', 'ECU_CERT_CA_LEN', 'ca_4', 4)

ECU_CERT_SIZE_HASH_TO_SIGN = 20
reg.reg_proj_config('Certification', 'ECU_CERT_SIZE_HASH_TO_SIGN', 'X509', 1000)  # 1 KB

ECU_CERT_SIZE_HASH = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE
reg.reg_proj_config('Certification', 'ECU_CERT_SIZE_HASH', 'CALC', ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size'])  # 1 KB
reg.reg_proj_config('Certification', 'ECU_CERT_SIZE_HASH', 'X509', 1000)  # 1 KB

SECMOD_CERT_HASHING_MECH = HashMechEnum.MD5
reg.reg_proj_config('Certification', 'SECMOD_CERT_HASHING_MECH', 'MD5', HashMechEnum.MD5)
reg.reg_proj_config('Certification', 'SECMOD_CERT_HASHING_MECH', 'SHA1', HashMechEnum.SHA1)
reg.reg_proj_config('Certification', 'SECMOD_CERT_HASHING_MECH', 'SHA256', HashMechEnum.SHA256)

SECMOD_CERT_ENCRYPTION_MECH = AsymAuthMechEnum.RSA
reg.reg_proj_config('Certification', 'SECMOD_CERT_ENCRYPTION_MECH', 'RSA', AsymAuthMechEnum.RSA)
reg.reg_proj_config('Certification', 'SECMOD_CERT_ENCRYPTION_MECH', 'ECC', AsymAuthMechEnum.ECC)

SECMOD_CERT_ENCRYPTION_MECH_OPTION = 3
reg.reg_proj_config('Certification', 'SECMOD_CERT_ENCRYPTION_MECH_OPTION', 'EXP_3', 3)
reg.reg_proj_config('Certification', 'SECMOD_CERT_ENCRYPTION_MECH_OPTION', 'EXP_5', 5)
reg.reg_proj_config('Certification', 'SECMOD_CERT_ENCRYPTION_MECH_OPTION', 'EXP_17', 17)
reg.reg_proj_config('Certification', 'SECMOD_CERT_ENCRYPTION_MECH_OPTION', 'EXP_257', 257)
reg.reg_proj_config('Certification', 'SECMOD_CERT_ENCRYPTION_MECH_OPTION', 'EXP_65537', 65537)

SECMOD_CERT_KEYL = AuKeyLengthEnum.bit_1024
reg.reg_proj_config('Certification', 'SECMOD_CERT_KEYL', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('Certification', 'SECMOD_CERT_KEYL', 'bit_256', AuKeyLengthEnum.bit_256)
reg.reg_proj_config('Certification', 'SECMOD_CERT_KEYL', 'bit_384', AuKeyLengthEnum.bit_384)
reg.reg_proj_config('Certification', 'SECMOD_CERT_KEYL', 'bit_512', AuKeyLengthEnum.bit_512)
reg.reg_proj_config('Certification', 'SECMOD_CERT_KEYL', 'bit_1024', AuKeyLengthEnum.bit_1024)
reg.reg_proj_config('Certification', 'SECMOD_CERT_KEYL', 'bit_2048', AuKeyLengthEnum.bit_2048)

SECMOD_CERT_CA_LEN = 1
reg.reg_proj_config('Certification', 'SECMOD_CERT_CA_LEN', 'ca_1', 1)
reg.reg_proj_config('Certification', 'SECMOD_CERT_CA_LEN', 'ca_2', 2)
reg.reg_proj_config('Certification', 'SECMOD_CERT_CA_LEN', 'ca_3', 3)
reg.reg_proj_config('Certification', 'SECMOD_CERT_CA_LEN', 'ca_4', 4)

SECMOD_CERT_SIZE_HASH_TO_SIGN = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE
reg.reg_proj_config('Certification', 'SECMOD_CERT_SIZE_HASH_TO_SIGN', 'CALC', ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size'])  # 1 KB
reg.reg_proj_config('Certification', 'SECMOD_CERT_SIZE_HASH_TO_SIGN', 'X509', 1000)  # 1 KB

SECMOD_CERT_SIZE_HASH_SIGNED = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE
reg.reg_proj_config('Certification', 'SECMOD_CERT_SIZE_HASH_SIGNED', 'CALC', ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size'])  # 1 KB
reg.reg_proj_config('Certification', 'SECMOD_CERT_SIZE_HASH_SIGNED', 'X509', 1000)  # 1 KB

#===============================================================================
#     ECU Authentication
#===============================================================================
# Interval to repeat the ECU Authentication
SSMA_ECU_AUTH_INTERVAL = 0
reg.reg_proj_config('ECUAuthentication', 'SSMA_ECU_AUTH_INTERVAL', 'SHORT', 100)
reg.reg_proj_config('ECUAuthentication', 'SSMA_ECU_AUTH_INTERVAL', 'LONG', 1000)
reg.reg_proj_config('ECUAuthentication', 'SSMA_ECU_AUTH_INTERVAL', 'INFINITY', sys.maxsize)

# Asymmetric Algorithm used in the Security Module
SSMA_SECM_PUB_ENC_ALG = AsymAuthMechEnum.RSA
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_ALG', 'RSA', AsymAuthMechEnum.RSA)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_ALG', 'ECC', AsymAuthMechEnum.ECC)

SSMA_SECM_PUB_ENC_ALG_OPTION = 3
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_ALG_OPTION', 'EXP_3', 3)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_ALG_OPTION', 'EXP_5', 5)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_ALG_OPTION', 'EXP_17', 17)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_ALG_OPTION', 'EXP_257', 257)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_ALG_OPTION', 'EXP_65537', 65537)

SSMA_SECM_PUB_ENC_KEY_LEN = AuKeyLengthEnum.bit_512
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_KEY_LEN', 'bit_384', AuKeyLengthEnum.bit_384)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_KEY_LEN', 'bit_512', AuKeyLengthEnum.bit_512)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_KEY_LEN', 'bit_1024', AuKeyLengthEnum.bit_1024)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_PUB_ENC_KEY_LEN', 'bit_2048', AuKeyLengthEnum.bit_2048)

# ECU Authentication: Symmetric Key of ECU (Encryption Algorithm) used for ECU Authentication
SCCM_ECU_SYM_KEY_ENC_ALG = SymAuthMechEnum.AES
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_SYM_KEY_ENC_ALG', 'AES', SymAuthMechEnum.AES)

SCCM_ECU_SYM_KEY_ENC_ALG_MODE = SymAuthMechEnum.CBC
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_SYM_KEY_ENC_ALG_MODE', 'CCM', SymAuthMechEnum.CCM)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_SYM_KEY_ENC_ALG_MODE', 'CBC', SymAuthMechEnum.CBC)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_SYM_KEY_ENC_ALG_MODE', 'CMAC', SymAuthMechEnum.CMAC)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_SYM_KEY_ENC_ALG_MODE', 'ECB', SymAuthMechEnum.ECB)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_SYM_KEY_ENC_ALG_MODE', 'CTR', SymAuthMechEnum.CTR)

SCCM_ECU_SYM_KEY_ENC_KEY_LEN = AuKeyLengthEnum.bit_1024
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_SYM_KEY_ENC_KEY_LEN', 'bit_128', AuKeyLengthEnum.bit_128)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_SYM_KEY_ENC_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_SYM_KEY_ENC_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)

# ECU Authentication: Asymetric Algorithm used in the ECUs comm Module
SCCM_ECU_PUB_ENC_ALG = AsymAuthMechEnum.ECC
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_ALG', 'ECC', AsymAuthMechEnum.ECC)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_ALG', 'RSA', AsymAuthMechEnum.RSA)
 
SCCM_ECU_PUB_ENC_ALG_OPTION = 5
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_ALG_OPTION', 'EXP_3', 3)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_ALG_OPTION', 'EXP_5', 5)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_ALG_OPTION', 'EXP_17', 17)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_ALG_OPTION', 'EXP_257', 257)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_ALG_OPTION', 'EXP_65537', 65537)
 
SCCM_ECU_PUB_ENC_KEY_LEN = AuKeyLengthEnum.bit_128
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_KEY_LEN', 'bit_384', AuKeyLengthEnum.bit_384)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_KEY_LEN', 'bit_512', AuKeyLengthEnum.bit_512)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_KEY_LEN', 'bit_1024', AuKeyLengthEnum.bit_1024)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_PUB_ENC_KEY_LEN', 'bit_2048', AuKeyLengthEnum.bit_2048)

# ECU Authentication: Hashing Algorithm used for the hashing in the REGISTRATION Message
SCCM_ECU_REG_MSG_HASH = HashMechEnum.MD5
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_REG_MSG_HASH', 'MD5', HashMechEnum.MD5)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_REG_MSG_HASH', 'SHA1', HashMechEnum.SHA1)
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_REG_MSG_HASH', 'SHA256', HashMechEnum.SHA256)

# ECU Authentication: Hashing Algorithm output length used for the hashing in the REGISTRATION Message
SCCM_ECU_REG_MSG_HASH_LEN = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# Size of the content of the inner registration message part
SSMA_REG_MSG_CT_SIZE_INNER = 0
reg.reg_proj_config('ECUAuthentication', 'SSMA_REG_MSG_CT_SIZE_INNER', 'DEFAULT', 200)

# Size of the content of the inner registration message part after encryption
SSMA_REG_MSG_CIPHER_SIZE_INNER = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# Size of the content of the outer registration message part after encryption
SSMA_REG_MSG_CIPHER_SIZE_OUTER = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# Size of the confirmation message before encryption
SCCM_ECU_CONF_MSG_SIZE = 0
reg.reg_proj_config('ECUAuthentication', 'SCCM_ECU_CONF_MSG_SIZE', 'DEFAULT', 200)

# Size of the confirmation message after encryption
SCCM_ECU_CONF_MSG_CIPHER_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size'] 


#===============================================================================
#     Stream Authorization
#===============================================================================
# Symmetric Session Key used in the Security Module
SSMA_SECM_SES_KEY_ENC_ALG = SymAuthMechEnum.AES
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_ENC_ALG', 'AES', SymAuthMechEnum.AES)

SSMA_SECM_SES_KEY_ENC_ALG_MODE = SymAuthMechEnum.CBC
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_ENC_ALG_MODE', 'CCM', SymAuthMechEnum.CCM)
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_ENC_ALG_MODE', 'CBC', SymAuthMechEnum.CBC)
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_ENC_ALG_MODE', 'CMAC', SymAuthMechEnum.CMAC)
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_ENC_ALG_MODE', 'ECB', SymAuthMechEnum.ECB)
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_ENC_ALG_MODE', 'CTR', SymAuthMechEnum.CTR)

SSMA_SECM_SES_KEY_ENC_KEY_LEN = AuKeyLengthEnum.bit_128
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_ENC_KEY_LEN', 'bit_128', AuKeyLengthEnum.bit_128)
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_ENC_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_ENC_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)

SSMA_SECM_SES_KEY_VALIDITY = 0  # Time the Session key will remain valid
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_VALIDITY', 'SHORT', 5)
reg.reg_proj_config('StreamAuthorization', 'SSMA_SECM_SES_KEY_VALIDITY', 'INFINITY', sys.maxsize)

# Size of the content that will be encrypted
SSMA_SIZE_REQ_MSG_CONTENT = 10
reg.reg_proj_config('StreamAuthorization', 'SSMA_SIZE_REQ_MSG_CONTENT', 'DEFAULT', 200)

SSMA_SIZE_REQ_MSG_CIPHER = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# Size of the grant message before encryption
SSMA_GRANT_MSG_CT_SIZE = 0
reg.reg_proj_config('StreamAuthorization', 'SSMA_GRANT_MSG_CT_SIZE', 'DEFAULT', 200)

# Size of the grant message after encryption
SSMA_GRANT_MSG_CIPHER_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# Stream Authorization: Maximum waiting time for response from Security Module after Authorization request
SCCM_MAX_WAIT_TIMEOUT = 200000000
reg.reg_proj_config('StreamAuthorization', 'SCCM_MAX_WAIT_TIMEOUT', 'DEFAULT', 200)

# Hold the Stream
SSMA_STREAM_HOLD = False
reg.reg_proj_config('StreamAuthorization', 'SSMA_STREAM_HOLD', 'HOLD', True)
reg.reg_proj_config('StreamAuthorization', 'SSMA_STREAM_HOLD', 'DROP', False)

# Minimum time between streams
SSMA_STREAM_MIN_INTERVAL = 5
reg.reg_proj_config('StreamAuthorization', 'SSMA_STREAM_MIN_INTERVAL', 'DEFAULT', 5)


#===============================================================================
#     Sending Sizes
#===============================================================================

# Sending Size of a ECU certificate
ECU_CERT_SIZE = 0
reg.reg_proj_config('Certification', 'ECU_CERT_SIZE', 'X509', 1000)  # 1 KB

# ECU Authentication: Size of the Registration message for the ECU Authentication [sending purpose only]
SCCM_ECU_REG_MSG_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# Security Modules Certificate Length in Byte [for sending purpose]
SSMA_SECM_CERT_SIZE = 0
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_CERT_SIZE', 'SMALL', 100)
reg.reg_proj_config('ECUAuthentication', 'SSMA_SECM_CERT_SIZE', 'X509', 1000)  # 1 KB

# Security Modules confirmation Message Size in Byte [for sending purpose]
SSMA_SECM_CONF_MSG_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# Security Modules Grant Message Size in Byte [for sending purpose]
SSMA_SECM_GRANT_MSG_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# Security Modules confirmation Message Size in Byte [for sending purpose]
SSMA_SECM_DENY_MSG_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# Stream Authorization: Size of the request message [sending purpose only]
SCCM_ECU_REQ_MSG_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE


#===============================================================================
#     TLS
#===============================================================================

TLSRL_PROTOCOL_VERSION = [3, 3]
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSRL_PROTOCOL_VERSION', 'DEFAULT', [3, 3])

# Compression in Recordlayer
TLSR_COMPRESSION_ALGORITHM = CompressionMethod.NULL
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_COMPRESSION_ALGORITHM', 'DEFAULT', CompressionMethod.NULL)

TLSR_COMPRESSED_SIZE = ['components.security.encryption.encryption_tools.CompressedSize', 'output_size'] 

# MAC Creation in Recordlayer
TLSR_DEC_BLOCKCIPHER_MAC_INPUT_SIZE = 60
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_DEC_BLOCKCIPHER_MAC_INPUT_SIZE', 'DEFAULT', 60)

TLSR_BLOCKCIPHER_MAC_INPUT_SIZE = 60
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_MAC_INPUT_SIZE', 'DEFAULT', 60)

TLSR_BLOCKCIPHER_MAC_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSR_DEC_BLOCKCIPHER_MAC_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSR_BLOCKCIPHER_MAC_ALGORITHM = SymAuthMechEnum.AES
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_MAC_ALGORITHM', 'AES', SymAuthMechEnum.AES)

TLSR_BLOCKCIPHER_MAC_KEY_LEN = AuKeyLengthEnum.bit_128
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_MAC_KEY_LEN', 'bit_128', AuKeyLengthEnum.bit_128)  # 16 Byte

# Symmetric Encryption in Recordlayer
TLSR_BLOCKCIPHER_ENC_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSR_BLOCKCIPHER_ENC_ALGORITHM = SymAuthMechEnum.AES
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_ENC_ALGORITHM', 'AES', SymAuthMechEnum.AES)

TLSR_BLOCKCIPHER_ENC_KEY_LEN = AuKeyLengthEnum.bit_128
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_ENC_KEY_LEN', 'bit_128', AuKeyLengthEnum.bit_128)
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_ENC_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_ENC_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)

TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE = SymAuthMechEnum.CBC
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE', 'CCM', SymAuthMechEnum.CCM)
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE', 'CBC', SymAuthMechEnum.CBC)
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE', 'CMAC', SymAuthMechEnum.CMAC)
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE', 'ECB', SymAuthMechEnum.ECB)
reg.reg_proj_config('TLS_RECORD_LAYER', 'TLSR_BLOCKCIPHER_ENC_ALGORITHM_MODE', 'CTR', SymAuthMechEnum.CTR)

# TLS Handshake Processes
TLSH_CLIENT_HELLO_SEND_SIZE = 60
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_HELLO_SEND_SIZE', 'DEFAULT', 60)

# TLS Certificate Server
TLSH_SERV_CERT_ENC_ALG = AsymAuthMechEnum.RSA
reg.reg_proj_config('TLS_HANDSHAKE', 'SCCM_ECU_PUB_ENC_ALG', 'ECC', AsymAuthMechEnum.ECC)
reg.reg_proj_config('TLS_HANDSHAKE', 'SCCM_ECU_PUB_ENC_ALG', 'RSA', AsymAuthMechEnum.RSA)

TLSH_SERV_CERT_ENC_ALG_OPTION = 5
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_ALG_OPTION', 'EXP_3', 3)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_ALG_OPTION', 'EXP_5', 5)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_ALG_OPTION', 'EXP_17', 17)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_ALG_OPTION', 'EXP_257', 257)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_ALG_OPTION', 'EXP_65537', 65537)

TLSH_SERV_CERT_ENC_KEY_LEN = AuKeyLengthEnum.bit_1024
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_KEY_LEN', 'bit_384', AuKeyLengthEnum.bit_384)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_KEY_LEN', 'bit_512', AuKeyLengthEnum.bit_512)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_KEY_LEN', 'bit_1024', AuKeyLengthEnum.bit_1024)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_ENC_KEY_LEN', 'bit_2048', AuKeyLengthEnum.bit_2048)

TLSH_SERV_CERT_HASH_MECH = HashMechEnum.MD5
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_HASH_MECH', 'MD5', HashMechEnum.MD5)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_HASH_MECH', 'SHA1', HashMechEnum.SHA1)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_HASH_MECH', 'SHA256', HashMechEnum.SHA256)

TLSH_CLIENT_CERT_CA_LEN = 1
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_CA_LEN', 'DEFAULT', 1)

TLSH_CLIENT_CERT_UNSIGNED_SIZE = 1300
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_UNSIGNED_SIZE', 'X509', 1300)

TLSH_CLIENT_CERT_SIGNED_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSH_CLIENT_CERT_HASH_MECH = HashMechEnum.MD5
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_HASH_MECH', 'MD5', HashMechEnum.MD5)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_HASH_MECH', 'SHA1', HashMechEnum.SHA1)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_HASH_MECH', 'SHA256', HashMechEnum.SHA256)

TLSH_SERV_CERT_CA_LEN = 1
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_CA_LEN', 'DEFAULT', 1)

TLSH_SERV_CERT_UNSIGNED_SIZE = 1300
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERV_CERT_UNSIGNED_SIZE', 'X509', 1300)

TLSH_SERV_CERT_SIGNED_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSH_CERT_VERIFY_CLEAR_SIZE = 100
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CERT_VERIFY_CLEAR_SIZE', 'DEFAULT', 100)

TLSH_CERT_VERIFY_CIPHER_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSH_PRF_MASTER_SEC_GENERATION = PRF.DUMMY
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_PRF_MASTER_SEC_GENERATION', 'DEFAULT', PRF.DUMMY)

TLSH_CLIENT_KEYEX_CIPHER_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSH_CLIENT_KEYEX_CLEAR_SIZE = 100
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_KEYEX_CLEAR_SIZE', 'DEFAULT', 100)


TLSH_CLIENT_CERT_ENC_ALG = AsymAuthMechEnum.ECC
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_ALG', 'ECC', AsymAuthMechEnum.ECC)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_ALG', 'RSA', AsymAuthMechEnum.RSA)

TLSH_CLIENT_CERT_ENC_ALG_OPTION = 5
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_ALG_OPTION', 'EXP_3', 3)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_ALG_OPTION', 'EXP_5', 5)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_ALG_OPTION', 'EXP_17', 17)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_ALG_OPTION', 'EXP_257', 257)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_ALG_OPTION', 'EXP_65537', 65537)

TLSH_CLIENT_CERT_ENC_KEY_LEN = AuKeyLengthEnum.bit_1024
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_KEY_LEN', 'bit_384', AuKeyLengthEnum.bit_384)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_KEY_LEN', 'bit_512', AuKeyLengthEnum.bit_512)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_KEY_LEN', 'bit_1024', AuKeyLengthEnum.bit_1024)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_CERT_ENC_KEY_LEN', 'bit_2048', AuKeyLengthEnum.bit_2048)

TLSH_SERVER_REC_FINISHED_CONTENT_SIZE = 100 
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERVER_REC_FINISHED_CONTENT_SIZE', 'DEFAULT', 3000)

TLSH_FINISH_MESSAGE_HASH_ALGORITHM = HashMechEnum.MD5
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_FINISH_MESSAGE_HASH_ALGORITHM', 'MD5', HashMechEnum.MD5)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_FINISH_MESSAGE_HASH_ALGORITHM', 'SHA1', HashMechEnum.SHA1)
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_FINISH_MESSAGE_HASH_ALGORITHM', 'SHA256', HashMechEnum.SHA256)

TLSH_SERVER_REC_FINISHED_HASH_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSH_SERVER_REC_FINISHED_PRF_ALG = PRF.DUMMY
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_PRF_MASTER_SEC_GENERATION', 'DEFAULT', PRF.DUMMY)

TLSH_CLIENT_REC_FINISHED_PRF_ALG = PRF.DUMMY
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_REC_FINISHED_PRF_ALG', 'DEFAULT', PRF.DUMMY)

TLSH_CLIENT_REC_FINISHED_CONTENT_SIZE = 100 
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_REC_FINISHED_CONTENT_SIZE', 'DEFAULT', 3000)

TLSH_CLIENT_REC_FINISHED_HASH_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSH_SERVER_SEND_FINISHED_HASH_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSH_SERVER_SEND_FINISHED_CONTENT_SIZE = 100 
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERVER_SEND_FINISHED_CONTENT_SIZE', 'DEFAULT', 3000)

TLSH_SERVER_SEND_FINISHED_PRF_ALG = PRF.DUMMY
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERVER_SEND_FINISHED_PRF_ALG', 'DEFAULT', PRF.DUMMY)

TLSH_CLIENT_SEND_FINISHED_PRF_ALG = PRF.DUMMY
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_SEND_FINISHED_PRF_ALG', 'DEFAULT', PRF.DUMMY)

TLSH_CLIENT_SEND_FINISHED_HASH_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

TLSH_CLIENT_SEND_FINISHED_CONTENT_SIZE = 100 
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CLIENT_SEND_FINISHED_CONTENT_SIZE', 'DEFAULT', 3000)

TLSH_CERT_REQUEST_SEND_SIZE = 250 
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CERT_REQUEST_SEND_SIZE', 'DEFAULT', 100)

TLSH_CERT_SEND_SIZE = 1000  # Size of one certificate when it is sent
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_CERT_SEND_SIZE', 'X509', 1000)

TLSH_SERVER_HELLO_SEND_SIZE = 60
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERVER_HELLO_SEND_SIZE', 'DEFAULT', 100)

TLSH_SERVER_HELLO_DONE_SEND_SIZE = 10
reg.reg_proj_config('TLS_HANDSHAKE', 'TLSH_SERVER_HELLO_DONE_SEND_SIZE', 'DEFAULT', 10)

#===============================================================================
#     TESLA
#===============================================================================

# Chain length for Key creation
TESLA_KEY_CHAIN_LEN = 100000
reg.reg_proj_config('TESLA', 'TESLA_KEY_CHAIN_LEN', 'DEFAULT', 100000)

# MAC Algorithm used
TESLA_MAC_KEY_ALGORITHM = SymAuthMechEnum.AES
reg.reg_proj_config('TESLA', 'TESLA_MAC_KEY_ALGORITHM', 'AES', SymAuthMechEnum.AES)

TESLA_MAC_KEY_LEN = AuKeyLengthEnum.bit_128
reg.reg_proj_config('TESLA', 'TESLA_MAC_KEY_LEN', 'bit_128', AuKeyLengthEnum.bit_128)
reg.reg_proj_config('TESLA', 'TESLA_MAC_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('TESLA', 'TESLA_MAC_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)

TESLA_MAC_SIZE_TRANSMIT = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE

# PRF Method used to create the Key Chain
TESLA_PRF_KEY_CHAIN = PRF.DUMMY
reg.reg_proj_config('TESLA', 'TESLA_PRF_KEY_CHAIN', 'DUMMY', PRF.DUMMY)

# PRF Method used to generate the MAC Key
TESLA_PRF_MAC_KEY = PRF.DUMMY    
reg.reg_proj_config('TESLA', 'TESLA_PRF_MAC_KEY', 'DUMMY', PRF.DUMMY)


TESLA_KEY_LEGID_MAC_ALGORITHM = SymAuthMechEnum.AES
reg.reg_proj_config('TESLA', 'TESLA_KEY_LEGID_MAC_ALGORITHM', 'AES', SymAuthMechEnum.AES)
       
TESLA_KEY_LEGID_MAC_KEY_LEN = AuKeyLengthEnum.bit_128
reg.reg_proj_config('TESLA', 'TESLA_KEY_LEGID_MAC_KEY_LEN', 'bit_128', AuKeyLengthEnum.bit_128)
reg.reg_proj_config('TESLA', 'TESLA_KEY_LEGID_MAC_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('TESLA', 'TESLA_KEY_LEGID_MAC_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)
       
# Initial Key exchange: Public/Private De/Encyption
TESLA_KEY_EXCHANGE_ENC_ALGORITHM = AsymAuthMechEnum.RSA
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_ENC_ALGORITHM', 'ECC', AsymAuthMechEnum.ECC)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_ENC_ALGORITHM', 'RSA', AsymAuthMechEnum.RSA)

TESLA_KEY_EXCHANGE_KEY_LEN = AuKeyLengthEnum.bit_1024
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_KEY_LEN', 'bit_192', AuKeyLengthEnum.bit_192)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_KEY_LEN', 'bit_256', AuKeyLengthEnum.bit_256)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_KEY_LEN', 'bit_384', AuKeyLengthEnum.bit_384)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_KEY_LEN', 'bit_512', AuKeyLengthEnum.bit_512)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_KEY_LEN', 'bit_1024', AuKeyLengthEnum.bit_1024)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_KEY_LEN', 'bit_2048', AuKeyLengthEnum.bit_2048)

TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION = 3      
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION', 'EXP_3', 3)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION', 'EXP_5', 5)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION', 'EXP_17', 17)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION', 'EXP_257', 257)
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_ENC_ALGORITHM_OPTION', 'EXP_65537', 65537)

# Clear Size of the key exchange message
TESLA_KEY_EXCHANGE_CLEAR_SIZE = 100
reg.reg_proj_config('TESLA', 'TESLA_KEY_EXCHANGE_CLEAR_SIZE', 'DEFAULT', 100)

# Cipher Size of the key exchange message
TESLA_KEY_EXCHANGE_CIPHER_SIZE = ['components.security.encryption.encryption_tools.EncryptionSize', 'output_size']  # FIX VALUE


#===============================================================================
#        Calculations to determine actual values 
#===============================================================================

# Adds the created variables to the registration object
if create_raw_config_file:
    cfg = config_io.ConfigIO()
    cfg.generate_raw_cfg(reg, config_file_path, IniConfig.PROJECT)

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
