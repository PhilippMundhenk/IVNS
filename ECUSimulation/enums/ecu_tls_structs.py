from enums.tls_enums import TLSConnectionEnd, TLSCipherSuite, TLSCipherType
from enums.sec_cfg_enum import HashMechEnum, SymAuthMechEnum

class TLSSession(object):
    
    def __init__(self):
        self.session_id = None
        self.peer_cert = None
        self.cipher_spec = None
        self.master_secret = None
        self.is_resumable = False

class SignatureAndHashAlgorithm(object):
    
    def __init__(self, hash_alg, sign_alg):
        self.hash_alg = hash_alg
        self.sign_alg = sign_alg    

class TLSSecurityParameter(object):
    
    def __init__(self):
        self.entity = TLSConnectionEnd.UNDEFINED
        self.prf_algorithm = None
        self.bulk_cipher_algorithm = None
        self.bulk_cipher_algorithm_option = None
        
        self.cipher_type = None
        self.enc_key_length = None
        self.block_length = None
        self.fixed_iv_length = None
        self.record_iv_length = None    
        
        self.mac_algorithm = None
        self.mac_length = None
        self.mac_key_length = None
        
        self.compression_algorithm = None
        
        self.master_secret = None  # 48 Bytes
        self.client_random = None  # 32 Bytes
        self.server_random = None  # 32 Bytes
        
    def equals(self, alt_cipher):
        
        if self.entity == alt_cipher.entity and \
        self.prf_algorithm == alt_cipher.prf_algorithm  and \
        self.bulk_cipher_algorithm == alt_cipher.bulk_cipher_algorithm and \
        self.bulk_cipher_algorithm_option == alt_cipher.bulk_cipher_algorithm_option and \
        self.cipher_type == alt_cipher.cipher_type and \
        self.enc_key_length == alt_cipher.enc_key_length and \
        self.block_length == alt_cipher.block_length and \
        self.fixed_iv_length == alt_cipher.fixed_iv_length and \
        self.record_iv_length == alt_cipher.record_iv_length and \
        self.mac_algorithm == alt_cipher.mac_algorithm and \
        self.mac_length == alt_cipher.mac_length and \
        self.mac_key_length == alt_cipher.mac_key_length and \
        self.compression_algorithm == alt_cipher.compression_algorithm and \
        self.master_secret == alt_cipher.master_secret and \
        self.client_random == alt_cipher.client_random and \
        self.server_random == alt_cipher.server_random:
            return True
        return False
            
    def from_cipher_suite(self, connections_end, cipher_suite, compression_alg, master_secret, server_random, client_random, prf_algorithm):
        self.entity = connections_end
        
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:            
            self.cipher_type = TLSCipherType.block
            self.enc_key_length = 0
            self.block_length = 8
            self.fixed_iv_length = 0
            self.record_iv_length = 0    
            self.mac_algorithm = None
            self.mac_length = 0
            self.mac_key_length = 16
            
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
            self.cipher_type = TLSCipherType.block
            self.enc_key_length = 16
            self.bulk_cipher_algorithm = SymAuthMechEnum.AES
            self.bulk_cipher_algorithm_option = SymAuthMechEnum.CBC
            self.block_length = 16
            self.fixed_iv_length = 16
            self.record_iv_length = 16    
            self.mac_algorithm = HashMechEnum.SHA1
            self.mac_length = 20
            self.mac_key_length = 16
            
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
            self.cipher_type = TLSCipherType.block
            self.enc_key_length = 16
            self.block_length = 16
            self.bulk_cipher_algorithm = SymAuthMechEnum.AES
            self.bulk_cipher_algorithm_option = SymAuthMechEnum.CBC
            self.fixed_iv_length = 16
            self.record_iv_length = 16    
            self.mac_algorithm = HashMechEnum.SHA256
            self.mac_length = 32
            self.mac_key_length = 16
            
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
            self.cipher_type = TLSCipherType.block
            self.enc_key_length = 32
            self.bulk_cipher_algorithm = SymAuthMechEnum.AES
            self.bulk_cipher_algorithm_option = SymAuthMechEnum.CBC
            self.block_length = 16
            self.fixed_iv_length = 16
            self.record_iv_length = 16    
            self.mac_algorithm = HashMechEnum.SHA1
            self.mac_length = 20
            self.mac_key_length = 16
            
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
            self.cipher_type = TLSCipherType.block
            self.enc_key_length = 32
            self.block_length = 16
            self.bulk_cipher_algorithm = SymAuthMechEnum.AES
            self.bulk_cipher_algorithm_option = SymAuthMechEnum.CBC
            self.fixed_iv_length = 16
            self.record_iv_length = 16    
            self.mac_algorithm = HashMechEnum.SHA256
            self.mac_length = 32
            self.mac_key_length = 16
            
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_NULL_MD5:
            self.cipher_type = None
            self.enc_key_length = 0
            self.block_length = 0
            self.fixed_iv_length = 0
            self.record_iv_length = 0    
            self.mac_algorithm = HashMechEnum.MD5
            self.mac_length = 16
            self.mac_key_length = 16
    
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_NULL_SHA:
            self.cipher_type = None
            self.enc_key_length = 0
            self.block_length = 0
            self.fixed_iv_length = 0
            self.record_iv_length = 0    
            self.mac_algorithm = HashMechEnum.SHA1
            self.mac_length = 20
            self.mac_key_length = 16
            
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_NULL_SHA256:
            self.cipher_type = None
            self.enc_key_length = 0
            self.block_length = 0
            self.fixed_iv_length = 0
            self.record_iv_length = 0    
            self.mac_algorithm = HashMechEnum.SHA256
            self.mac_length = 32
            self.mac_key_length = 16
            
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_RC4_128_MD5:
            self.cipher_type = TLSCipherType.stream
            self.enc_key_length = 0
            self.block_length = 0
            self.fixed_iv_length = 0
            self.record_iv_length = 0    
            self.mac_algorithm = HashMechEnum.MD5
            self.mac_length = 16
            self.mac_key_length = 16
            
        if cipher_suite == TLSCipherSuite.TLS_RSA_WITH_RC4_128_SHA:
            self.cipher_type = TLSCipherType.stream
            self.enc_key_length = 0
            self.block_length = 0
            self.fixed_iv_length = 0
            self.record_iv_length = 0    
            self.mac_algorithm = HashMechEnum.SHA1
            self.mac_length = 20
            self.mac_key_length = 16
            
        self.prf_algorithm = prf_algorithm
        self.compression_algorithm = compression_alg
        self.master_secret = master_secret  # 48 Bytes
        self.client_random = client_random  # 32 Bytes
        self.server_random = server_random  # 32 Bytes
            
class TLSPlaintext(object):
    
    def __init__(self, content_type=None, prot_version=None, length=None, fragment=None):
        self.content_type = content_type
        self.prot_version = prot_version
        self.length = length
        self.fragment = fragment
        
class TLSCompressed(object):
    
    def __init__(self, content_type=None, prot_version=None, length=None, fragment=None):
        self.content_type = content_type
        self.prot_version = prot_version
        self.length = length
        self.fragment = fragment
        
class TLSCiphertext(object):
    
    def __init__(self, content_type=None, prot_version=None, length=None, fragment=None):
        self.content_type = content_type
        self.prot_version = prot_version
        self.length = length
        self.fragment = fragment  # depends on TLSSecurityParameter.cipher_type -> stream: GenericStreamCipher, block: GenericBlockCipher, aead: GenericAEADCipher
        
        self.stream_id = None
        
class GenericStreamCipher(object):
    
    def __init__(self, content=None, mac=None):
        self.fragment = content
        self.mac = mac

class GenericBlockCipher(object):
    
    def __init__(self, iv=None, content=None, mac=None, padding=None, padding_length=None):
        self.iv = iv
        self.fragment = content
        self.mac = mac
        self.padding = padding
        self.padding_length = padding_length
        
class GenericAEADCipher(object):
    
    def __init__(self, content=None, nonce_explicit=None):
        self.fragment = content
        self.nonce_explicit = nonce_explicit
