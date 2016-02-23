import uuid
from components.security.encryption.encryption_tools import HashedMessage, \
    asy_encrypt


class EcuCertificate(object):
    ''' defined after X-509 Standard'''
    
    def __init__(self, version=None, signature_alg=None, signature_hash=None, cert_auth_list=None, valid_from=None, valid_till=None, user_id=None, pub_k_alg=None, pub_key=None, priv_key_owner=None):
        ''' Constructor
            
            Input:   version            float                version of the certificate
                     signature_alg      AsymAuthMechEnum     encryption algorithm used to sign this certificate
                     signature_hash     HashMechEnum         hashing method used to sign this certificate
                     cert_auth_list     list                 list of CA s that are able to verify this certificate
                     valid_from         float                start of validation time of the certificate
                     valid_till         float                end of validation time of the certificate
                     user_id            string               id of the certificate holder
                     pub_k_alg          AsymAuthMechEnum     encryption algorithm of this subject having the certificate
                     pub_key            AsymetricKey         public key of this certificate
                     priv_key_owner     AsymetricKey         private key of the next higher CA
            Output:  -
        '''     

        # basic information
        self.version = version  # e.g. 3
        self.serial_nr = uuid.uuid4()  # e.g. 1        
        self.cert_auth = cert_auth_list  # e.g. Steiermark Authority vouching for the certificates
        self.valid_from = valid_from  # e.g. 203
        self.valid_till = valid_till  # e.g. 403
        self.user_id = user_id  # e.g. HansHuber: only one that can verify the certificate that was provided to him  
        
        # public key of subject having certificate
        self.pub_key_alg = pub_k_alg  # e.g. rsaEncryption: That is the key used to verify the certificate
        self.pub_key = pub_key  # e.g. 00:c4:40:4c:6e:14:1b:61:36:84:24:b2:61:c0:b5:
        try: self.pub_key_len = pub_key.valid_key_len  # e.g. 1024 Bit
        except: pass
        
        # signature encrypted by the CA
        # digital signature = encrypt(hash(certificate_content)) private key of certificate authority used 
        self.signature_alg = signature_alg  # e.g. RSAEncryption&md5: algorithm used to sign digital signature
        self.signature_hash = signature_hash  # e.g. md5With
        self.signature = self._create_signiture(priv_key_owner)  # e.g. 12:ed:f7:b3:5e:a0:93:3f:a0:1d:60:cb:47:19:7d:15:59:9b:              
            
        self.size = 1000
            
    def _create_signiture(self, priv_key_owner):
        ''' signature = hashed and encrypted message
            create a signature signed with the priv_key_owner
            of the certificate owner 
            
            Input:  priv_key_owner    AsymetricKey        private key of the owner of the certificate
            Output: signature         EncryptedMessage    signature 
        '''
        try:
            signature = asy_encrypt(HashedMessage(self, self.signature_hash), priv_key_owner)      
            return signature
        except:
            return None
