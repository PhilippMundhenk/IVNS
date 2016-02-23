import uuid
from tools.singleton import Singleton
from enums.sec_cfg_enum import HashMechEnum, AsymAuthMechEnum, SymAuthMechEnum, \
    EnumTrafor
from math import floor
from tools.ecu_logging import ECULogger as L
import math
import logging


def asy_get_key_pair(algorithm, key_length, algorithm_option=False):
    ''' this method generates a public and a private key. Messages encrypted
        with each of those keys can only be decrypted using the other key.
        
        Input:  algorithm             AsymAuthMechEnum       enum defining the algorithm used for encryption 
                key_length            AuKeyLengthEnum        enum defining the key length used for encryption 
                algorithm_option      number/string/...      option for the encryption algorithm (e.g. RSA exponent)
        Output: private_key           AsymetricKey           private key used for de/encryption
                public_key            AsymetricKey           public key used for de/encryption
    '''
    # generate keys
    private_key = AsymetricKey(algorithm, key_length, algorithm_option)
    public_key = AsymetricKey(algorithm, key_length, algorithm_option)    
    
    # connect keys
    public_key.connect(private_key)
    private_key.connect(public_key)
    
    # result
    return private_key, public_key


def asy_encrypt(clear_text, asymmetric_key):
    ''' this method encrypts the clear text asymmetrically 
        with the given key 
        
        Input:  clear_text         object              object that will be encrypted using the given key
                asymmetric_key     AsymetricKey        key used for the encryption
        Output: cipher_text        EncryptedMessage    clear text that was encrypted using the given key
    '''
    # key invalid
    if asymmetric_key == None: return None
    
    # cipher text
    cipher_text = EncryptedMessage(clear_text, asymmetric_key.corresponding_key_id, asymmetric_key.valid_alg, asymmetric_key.valid_key_len)       
    
    # result
    return cipher_text


def asy_decrypt(cipher_text, asymmetric_key, now=float('-inf')):
    ''' this method decrypts the cipher text asymmetrically 
        with the given key . It also checks if the key is valid in 
        time if defined.
        
        Input:  cipher_text        EncryptedMessage    object that was encrypted using the pendant of the given key
                asymmetric_key     AsymetricKey        key that is the pendant of the key that was used for encryption
        Output: clear_text         object              decrypted clear text (using the given key)
    '''
    # same algorithms
    cond_1 = cipher_text.decryption_key_id == asymmetric_key.id
    cond_2 = cipher_text.decryption_alg == asymmetric_key.valid_alg
    cond_3 = cipher_text.decryption_key_len == asymmetric_key.valid_key_len
    cond_4 = True  # cipher.decryption_alg_mode == key.valid_alg_mode
    
    # valid time
    if asymmetric_key.valid_till != None:
        cond_4 = now <= asymmetric_key.valid_till
        if not cond_4: L().log(803, now, asymmetric_key.valid_till)
    
    # conditions ok
    if(cond_1 and cond_2 and cond_3 and cond_4):
        return cipher_text.msg_unencrpyted
    
    # not able to decrypt
    else:
        return None


def certificate_trustworthy(certificate, root_certificate_list, now):
    ''' this method checks if the given certificate can be 
        verified using the given list of root certificates, when 
        this test is made at the point in time now.
        
        Input:  certificate                 ECUCertificate      certificate that is to be verified
                root_certificates_list      list                list of root certificates
                now                         float               time in the simpy.Environment when this method 
                                                                is called
        Output: boolean                     bool                True if this certificate could be verified using the given    
                                                                root certificates
    ''' 
    
    # invalid certificate
    if certificate == None: return False    
    valid, next_certificate = True, certificate
    
    # check certificate layerwise
    while next_certificate != None:
        try:
            # ca certificate
            ca_certificate = find_auth(next_certificate, root_certificate_list)
            
            # integrity
            hashed = HashedMessage(next_certificate, next_certificate.signature_hash)
            
            # root
            if ca_certificate == None: 
                signature = asy_decrypt(next_certificate.signature, next_certificate.pub_key_user)
            
            # no root
            else: 
                signature = asy_decrypt(next_certificate.signature, ca_certificate.pub_key_user)
            
            # integrity failed
            if not signature.same_hash(hashed): 
                return False
            
            # expiry        
            if not (now < next_certificate.valid_till and now > next_certificate.valid_from):
                return False
            
            # next layer
            next_certificate = ca_certificate
        except:
            L().log(804, next_certificate)
            return False
    
    return valid


def compress(text, algorithm):
    ''' compresses the given text using the 
        given compression algorithm
    
        Input:  text               object                text that will be compressed
                algorithm          CompressionMethod     enum defining the compression method used
        Output: compressed_text    CompressedMessage     message after having been compressed
    '''
    return CompressedMessage(text, algorithm)


def decompress(compressed_message, alg):    
    ''' decompresses the given CompressedMessage using the 
        given compression algorithm
    
        Input:  compressed_text    CompressedMessage     message after having been compressed                
                algorithm          CompressionMethod     enum defining the compression method used
        Output: text               object                text that was decompressed
    '''
    try:
        if compressed_message.compression_alg == alg:
            return compressed_message.msg
        else:
            return None
    except:
        return None
    return None


def find_auth(ref_certificate, root_certificates_list):
    ''' this method gets a list of root certificates and finds the 
        certificate which belongs to the CA which signed the 
        certificate ref_certificate
        
        Input:  ref_certificate            ECUCertificate   ECU certificate which is investigated
                root_certificates_list     list             list of root certificates
        Output: certificate                ECUCertificate   the root certificate corresponding to the 
                                                            certification authority that signed the given 
                                                            certificate ref_certificate
    '''
    # iterate certificates
    for certificate in root_certificates_list:
        if certificate.user_id == ref_certificate.cert_auth:
            return certificate
        
    # no result found
    return None


def mac(clear_text, mac_key):
    ''' applies a mac algorithm with the given key
        to the given clear text
        Input:  clear_text    object    object that the MAC algorithm will be used on
                mac_key       MACKey    key of the mac 
        Output: mac           MAC       text after the mac algorithm was applied 
    '''
    return MAC(clear_text, mac_key)


def same_mac(mac_1, mac_2):
    ''' compares mac_1 to mac_2 and returns
        True if they are equal if only the key to
        encryption is considered
        
        Input:  mac_1        MAC    first MAC
                mac_2        MAC    second MAC
        Output: boolean      bool   True if both MACs passed are equal 
    '''
    # same key used
    if mac_1.key.id == mac_2.key.id:
        return True

    return False


def same_mac_ct(mac_1, mac_2):
    ''' compares mac_1 to mac_2 and returns
        True if they are equal if both the key to
        encryption and the content of the MAC are considered
        
        Input:  mac_1        MAC    first MAC
                mac_2        MAC    second MAC
        Output: boolean      bool   True if both MACs passed are equal 
    '''
    try:
        if mac_1.key.id == mac_2.key.id and mac_1.msg == mac_2.msg:
            return True
    except:
        return False
    return False


def sym_get_key(algorithm, key_length, algorithm_mode=False, predefined_key_id=False):
    ''' this method generates a symmetric key. Messages encrypted
        with this keys can only be decrypted using the same key.
        
        Input:  algorithm           SymAuthMechEnum          enum defining the algorithm used for encryption 
                key_length          SymAuthMechEnum          enum defining the key length used for encryption 
                algorithm_mode      SymAuthMechEnum          option for the encryption algorithm (e.g. AES: CTR Mode)
                predefined_key_id   uuid                     this id is compared when messages are decrypted. So if this
                                                             optional argument is given equal keys can be generated
        Output: symmetric_key       SymmetricKey             key used for de/encryption
    '''
    # create key
    symmetric_key = SymmetricKey(algorithm, algorithm_mode, key_length, predefined_key_id)
    
    # result
    return symmetric_key


def sym_encrypt(clear_text, symmetric_key):
    ''' this method encrypts the clear text symmetrically 
        with the given key 
        
        Input:  clear_text         object              object that will be encrypted using the given key
                symmetric_key      SymmetricKey        key used for the encryption
        Output: cipher_text        EncryptedMessage    clear text that was encrypted using the given key
    '''
    return EncryptedMessage(clear_text, symmetric_key.id, symmetric_key.valid_alg, symmetric_key.valid_key_len, symmetric_key.valid_alg_mode)          

# symmetric decryption

sym_decrypt = asy_decrypt


class MACSize(Singleton):
    '''
    this class is used to map the size of an input before 
    having used a certain MAC algorithm to the size after 
    the MAC procedure 
    '''
    
    
    def output_size(self, input_size, algorithm, key_length):  # Todo: Implement maybe
        ''' maps the size of an input before 
            having used a certain MAC algorithm to the size after 
            the MAC procedure using the defined algorithm and
            key_length
            
            Input:  input_size   float               size of the text before MAC algorithm application 
                    algorithm    MACAlgorithm        algorithm of the MAC procedure
                    key_length   AuKeyLengthEnum     key length used for the MAC procedures
            Output: output_size  float               size of the text after the MAC algorithm was applied
        '''
        return input_size

class CompressedSize(Singleton):
    '''
    this class is used to map the size of an input before 
    having used a certain compression algorithm to the size after 
    the compression procedure 
    '''
    
    def output_size(self, input_size, algorithm):  # Todo: Implement maybe
        ''' maps the size of an input before 
            having used a certain compression algorithm to the size after 
            the compression procedure using the defined algorithm
            
            Input:  input_size   float               size of the text before compression algorithm application 
                    algorithm    CompressionMethod   enum defining the compression method
            Output: output_size  float               size of the text after the compression algorithm was applied
        '''
        return input_size

class EncryptionSize(Singleton):
    ''' calculates a message size after it was encrypted/hashed/signed with a 
        certain algorithm'''
    
    
    def output_size(self, input_size, algorithm, key_length, mode):
        ''' maps the size of an input before 
            having used a certain encryption algorithm to the size after 
            the encryption procedure using the defined algorithm and
            key_length
            
            Input:  input_size   float                               size of the text before encryption algorithm application 
                    algorithm    AsymAuthMechEnum/SymAuthMechEnum    algorithm of the encryption procedure
                    key_length   AuKeyLengthEnum                     key length used for the encryption procedures
            Output: output       float                               size of the text after the MAC algorithm was applied
        '''
        output = None
        if mode == 'HASH':     
            if algorithm == HashMechEnum.MD5:
                output = self._md5_output(input_size)
            elif algorithm == HashMechEnum.SHA1:
                output = self._sha1_output(input_size)
            elif algorithm == HashMechEnum.SHA256:
                output = self._sha256_output(input_size)
    
        elif mode == 'SIGN':
            if algorithm == AsymAuthMechEnum.ECC:
                output = self._ecc_sign_output(input_size, key_length)
            elif algorithm == AsymAuthMechEnum.RSA:
                output = self._rsa_sign_output(input_size, key_length)

        elif mode == 'VERIFY':
            if algorithm == AsymAuthMechEnum.ECC:
                output = self._ecc_verify_output(input_size, key_length)
            elif algorithm == AsymAuthMechEnum.RSA:
                output = self._rsa_verify_output(input_size, key_length)
            
        elif mode == 'ENCRYPTION':
            if algorithm == AsymAuthMechEnum.ECC:
                output = self._ecc_enc_output(input_size, key_length)
            elif algorithm == AsymAuthMechEnum.RSA:
                output = self._rsa_enc_output(input_size, key_length)            
            elif algorithm == SymAuthMechEnum.AES:
                output = self._aes_enc_output(input_size, key_length)
        
        elif mode == 'DECRYPTION':
            if algorithm == AsymAuthMechEnum.ECC:
                output = self._ecc_dec_output(input_size, key_length)
            elif algorithm == AsymAuthMechEnum.RSA:
                output = self._rsa_dec_output(input_size, key_length)            
            elif algorithm == SymAuthMechEnum.AES:
                output = self._aes_dec_output(input_size, key_length)
    
        if output < 0:
            logging.warn("Error Output smaller than allowed %s, %s, %s, %s" % (input_size, algorithm, key_length, mode))
    
        if output == None:
            L().log_warn(805)
            return input_size

        return output
    
    
    def _md5_output(self, input_size):
        ''' independent of input always 16
            
            Input:  input_size     float     size before algorithm applied
            Output: output_size    float     size after algorithm applied
        '''
        return 16
    
    
    def _sha1_output(self, input_size):
        ''' independent of input always 20
            
            Input:  input_size     float     size before algorithm applied
            Output: output_size    float     size after algorithm applied
        '''
        return 20
        
    
    def _sha256_output(self, input_size):
        ''' independent of input always 32
            
            Input:  input_size     float     size before algorithm applied
            Output: output_size    float     size after algorithm applied
        '''
        return 32
    
        
    def _ecc_sign_output(self, input_size, key_length):
        ''' ECDSA - used by both cryptolib and CyaSSL
            -> Signs a hash
            
            Input:  input_size     float             size before algorithm applied
                    key_length     AuKeyLengthEnum   key length used for encryption 
            Output: output_size    float             size after algorithm applied
        '''
        key_len = EnumTrafor().to_value(key_length)        
        ecc_signature_size = 2 * (key_len / 8) + 6
        return ecc_signature_size
    
    
    def _rsa_sign_output(self, input_size, key_length):
        ''' size after signing 
            
            Input:  input_size     float             size before algorithm applied    
                    key_length     AuKeyLengthEnum   key length used for encryption
            Output: output_size    float             size after algorithm applied        
        '''
        nr_chuncks = math.ceil(input_size / (float(EnumTrafor().to_value(key_length) / 8) - 11))    
        if nr_chuncks <= 0: nr_chuncks = 1
        return (EnumTrafor().to_value(key_length) / 8) * nr_chuncks
    
    
    def _ecc_verify_output(self, input_size, key_length):
        ''' ECDSA - used by both cryptolib and CyaSSL
            -> Verifies a signature: 
                - hash the text
                - public decrypt 
            
            Input:  input_size     float             size before algorithm applied
                    key_length     AuKeyLengthEnum   key length used for encryption
            Output: output_size    float             size after algorithm applied
        '''
        return self._ecc_enc_output(input_size, key_length)
    
    
    def _rsa_verify_output(self, input_size, key_length):
        ''' no output size
            -> Verifies a signature: 
                - hash the text
                - public decrypt 
            
            Input:  input_size     float             size before algorithm applied
                    key_length     AuKeyLengthEnum   key length used for encryption
            Output: output_size    float             size after algorithm applied
        '''
        return self._rsa_enc_output(input_size, key_length)
    
    
    def _ecc_enc_output(self, input_size, key_length):
        ''' 
            always 1 - 16 = 48, 17 - 32 = 48 + 16, 33 -48 = 48 +2*16 ,... 
            
            Input:  input_size     float             size before algorithm applied
                    key_length     AuKeyLengthEnum   key length used for encryption
            Output: output_size    float             size after algorithm applied         
        '''
        for i in range(1, 500):
            if input_size < i * 16:
                return (48 + (i - 1) * 16)
        return None
    
    
    def _rsa_enc_output(self, input_size, key_length):
        ''' encryption = public encrypt
        
            when bigger than the keylength it is assumed that
            the message is chuncked
            
            input length per chunck is then keylen - 11
            
            Input:  input_size     float     size before algorithm applied
                    key_length     AuKeyLengthEnum   key length used for encryption
            Output: output_size    float     size after algorithm applied
        '''
        nr_chuncks = math.ceil(input_size / (float(EnumTrafor().to_value(key_length) / 8) - 11))    
        if nr_chuncks <= 0: nr_chuncks = 1
        return (EnumTrafor().to_value(key_length) / 8) * nr_chuncks
    
    
    def _aes_enc_output(self, input_size, key_length):
        ''' blocksize is 16 
            
            Input:  input_size     float             size before algorithm applied
                    key_length     AuKeyLengthEnum   key length used for encryption
            Output: output_size    float             size after algorithm applied
        '''
        nr = floor(input_size / 16)
        if nr <= 0: nr = 1
        
        if input_size % 16 == 0: 
            return nr * 16
        else: 
            return (nr * 16 + 16)
    
    
    def _aes_dec_output(self, input_size, key_length):
        ''' AES: size after decryption
            
            Input:  input_size     float             size before algorithm applied
                    key_length     AuKeyLengthEnum   key length used for encryption
            Output: output_size    float             size after algorithm applied
        '''
        return input_size

    
    def _ecc_dec_output(self, input_size, key_length):
        ''' ECC: size after decryption
            
            Input:  input_size     float             size before algorithm applied
                    key_length     AuKeyLengthEnum   key length used for encryption
            Output: output_size    float             size after algorithm applied
        '''
        for i in range(1, 500):
            if input_size < (48 + (i - 1) * 16):
                return i * 16 
    
    
    def _rsa_dec_output(self, input_size, key_length):
        ''' RSA: size after decryption
            
            Input:  input_size     float             size before algorithm applied
                    key_length     AuKeyLengthEnum   key length used for encryption
            Output: output_size    float             size after algorithm applied
        '''
        nr_chuncks = math.ceil(input_size / (float(EnumTrafor().to_value(key_length) / 8) - 11))    
        if nr_chuncks <= 0: nr_chuncks = 1
        return (EnumTrafor().to_value(key_length) / 8) * nr_chuncks
    
class MAC(object):
    '''
    this class resembles a text on which a MAC algorithm with 
    a certain key was applied
    '''
    def __init__(self, clear_text, mac_key):
        ''' Constructor
            
            Input:  clear_text    object    object that the MAC algorithm will be used on
                    mac_key       MACKey    key of the mac 
            Output: -
        
        '''
        self.msg = clear_text
        self.key = mac_key
        
class MACKey(object):
    '''
    this class resembles a key that can be used to create 
    a MAC with a defined algorithm
    '''
    def __init__(self, algorithm, key_length, predefined_id=False):
        ''' Constructor
            
            Input:  algorithm        MACAlgorithm           algorithm used for the MAC procedure
                    key_length       AuKeyLengthEnum        key length used for the MAC procedure
                    predefined_id    uuid                   this id is compared when messages are verified. So if this
                                                            optional argument is given equal keys can be generated
            Output: -
        '''
        # parameters
        self.id = uuid.uuid4()
        self.valid_alg = algorithm           
        self.valid_key_len = key_length
        
        # fixed id
        if predefined_id:
            self.id = predefined_id
            
class AsymetricKey(object):
    '''
    this class resembles a key that can be used to create 
    a EncryptedMessage with a defined algorithm
    '''
    def __init__(self, algorithm, key_length, algorithm_mode=False):
        ''' Constructor
            
            Input:  algorithm             AsymAuthMechEnum       enum defining the algorithm used for encryption 
                    key_length            AuKeyLengthEnum        enum defining the key length used for encryption 
                    algorithm_option      number/string/...      option for the encryption algorithm (e.g. RSA exponent)
            Output: -
        '''
        self.id = uuid.uuid4()
        self.corresponding_key_id = None
        self.valid_alg = algorithm
        self.valid_alg_mode = algorithm_mode
        self.valid_key_len = key_length
        self.valid_till = None

    
    def connect(self, key):
        ''' connects the passed AsymmetricKey to this key. The connected
            key can be used to decrypt messages encrypted with this key.
            
            Input:    key     Asymetric    key used for encryption
            Output:   -        
        '''
        self.corresponding_key_id = key.id
        
class SymmetricKey(object):
    '''
    this class resembles a key that can be used to create 
    a EncryptedMessage with a defined algorithm
    '''
    
    def __init__(self, valid_alg, valid_alg_mode, valid_key_len, predef_keyid=False):
        ''' Constructor
        
            Input:  algorithm           SymAuthMechEnum          enum defining the algorithm used for encryption 
                    key_length          SymAuthMechEnum          enum defining the key length used for encryption 
                    algorithm_mode      SymAuthMechEnum          option for the encryption algorithm (e.g. AES: CTR Mode)
                    predefined_key_id   uuid                     this id is compared when messages are decrypted. So if this
                                                                 optional argument is given equal keys can be generated
            Output: -
        '''
        # parameters
        self.id = uuid.uuid4()
        self.valid_alg = valid_alg
        self.valid_alg_mode = valid_alg_mode
        self.valid_key_len = valid_key_len
        self.valid_till = float('inf')
        
        # predefined key
        if predef_keyid:
            self.id = predef_keyid
        
    
    def set_validity(self, end_time):
        ''' this method sets the validity of this
            key
            
            Input:    end_time    float    time when this key will be invalid
            Output:   -
        '''
        self.valid_till = end_time

class CompressedMessage(object):
    '''
    this class resembles a key that can be used to create 
    a compressed text with a defined algorithm
    '''
    def __init__(self, text, compression_algorithm):
        ''' Constructor
        
            Input:  text               object                text that will be compressed
                    algorithm          CompressionMethod     enum defining the compression method used
            Output: -
        
        '''
        self.msg = text
        self.compression_alg = compression_algorithm
        
class EncryptedMessage(object):
    '''
    this class resembles a message that was encrypted with a specific algorithm
    with a key length, and a certain algorithm mode
    '''
    def __init__(self, clear_text, key_id, algorithm, key_length, algorithm_mode=False):
        ''' Constructor
        
            Input:  clear_text       object                            text that needs to be encrypted
                    key_id           uuid                              id of the key that is used for encryption
                                                                       (compared during decryption)
                    algorithm       AsymAuthMechEnum/SymAuthMechEnum   algorithm used for encryption
                    key_length      AuKeyLengthEnum                    key length used for encryption
                    algorithm_mode  number/string/..                   optional parameter used for encryption e.g. RSA exponent
        '''
        self.msg_unencrpyted = clear_text
        self.decryption_key_id = key_id
        self.decryption_alg = algorithm
        self.decryption_key_len = key_length
        self.decryption_alg_mode = algorithm_mode
        
class HashedMessage(object):
    '''
    this class resembles a message that was hashed with a specific algorithm
    '''
    
    def __init__(self, clear_text, hash_mechanism):
        ''' Constructor
            
            Input:  clear_text        object          text before hashing
                    hash_mechansim    HashMechEnum    hashing mechanism used for hashing
            Output: -
        '''
        self.msg_unhashed = clear_text
        self.hash_mechanism = hash_mechanism
        
    
    def same_hash(self, second_hash):
        ''' this method compares the current HashedMessage object with
            the HashedMessage object that was passed to this method
        
            Input:     second_hash    HashedMessage    hash that has to be compared
            Output:    bool           boolean          True if this hash is equal to the second_hash
        '''
        
        try:
            return (self.msg_unhashed.__dict__ == second_hash.msg_unhashed.__dict__) and (self.hash_mechanism == second_hash.hash_mechanism)
        except:
            if not (self.hash_mechanism == second_hash.hash_mechanism):
                return False
            
            for i in range(len(self.msg_unhashed)):               
                if self.msg_unhashed[i] == second_hash.msg_unhashed[i]:
                    continue
                
                if not self.msg_unhashed[i].__dict__ == second_hash.msg_unhashed[i].__dict__:
                    return False 
      
      
            return True
    
    
    def unhash(self):
        ''' this method returns the clear message after
            being unhashed (impossible in reality)
            
            Input: -
            Outut: clear_text    object        clear message 
        '''
        return self.msg_unhashed
    
