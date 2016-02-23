'''
Created on 1 Jul, 2015

@author: artur.mrowca
'''

from enum import Enum

class TLSState(Enum):
    NONE = -1
    
    CLIENT_HELLO_RECEIVED = 1
    CLIENT_HELLO_SENT = 2
    
    SERVER_HELLO_SENT = 3
    SERVER_HELLO_RECEIVED = 4
    
    SERVER_CERTIFICATE_SENT = 5
    SERVER_CERTIFICATE_RECEIVED = 6
    
    SERVER_KEYEXCHANGE_SENT = 7
    SERVER_KEYEXCHANGE_RECEIVED = 8
    
    CLIENT_CERTIFICATE_REQUEST_SENT = 9
    CLIENT_CERTIFICATE_REQUEST_RECEIVED = 10
    
    SERVER_HELLO_DONE_SENT = 11
    SERVER_HELLO_DONE_RECEIVED = 12
    
    CLIENT_CERTIFICATE_SENT = 13
    CLIENT_CERTIFICATE_RECEIVED = 14
    
    CLIENT_KEYEXCHANGE_SENT = 15
    CLIENT_KEYEXCHANGE_RECEIVED = 16
    
    CERTIFICATE_VERIFY_SENT = 17
    CERTIFICATE_VERIFY_RECEIVED = 18
    
    CHANGE_CIPHER_SPEC_SENT = 19
    CHANGE_CIPHER_SPEC_RECEIVED = 20
    
    FINISHED_SENT = 21
    FINISHED_RECEIVED = 22

    AUTHENTICATED = 23
    
    
    
class TLSConnectionEnd(Enum):
    SERVER = 1
    CLIENT = 2
    UNDEFINED = 3
    
class KeyexchangeAlgorithm(Enum):
    DHE_DSS = 1
    DHE_RSA = 2
    DH_ANON = 3
    RSA = 4
    DH_DSS = 5
    DH_RSA = 6
    
class TLSCertificateType(Enum):
    RSA_SIGN = 1
    ECC_SIGN = 2
    
class TLSContentType(Enum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    UNDEFINED = 255
    
class TLSCipherType(Enum):
    stream = 1
    block = 2
    aead = 3
    
class MACAlgorithm(Enum):
    HMAC_MD5 = 1
    HMAC_SHA1 = 2
    HMAC_SHA256 = 3
    HMAC_SHA384 = 4
    HMAC_SHA512 = 5
    NULL = 0
    
class PRFAlgorithm(Enum):
    TLS_PRF_SHA256 = 1
    
class BulkCipherAlgorithm(Enum):
    NULL = 0
    RC4 = 1
    DES3 = 2
    AES = 3
    
class CompressionMethod(Enum):
    NULL = 0
    V255 = 1
    
class TLSCipherSuite(Enum):
    TLS_RSA_WITH_NULL_MD5 = 1
    TLS_RSA_WITH_NULL_SHA = 2
    TLS_RSA_WITH_NULL_SHA256 = 3
    TLS_RSA_WITH_RC4_128_MD5 = 4
    TLS_RSA_WITH_RC4_128_SHA = 5
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 6
    TLS_RSA_WITH_AES_128_CBC_SHA = 7
    TLS_RSA_WITH_AES_256_CBC_SHA = 8
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 9
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 10
