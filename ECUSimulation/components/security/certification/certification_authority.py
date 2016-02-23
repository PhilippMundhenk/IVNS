from components.security.encryption import encryption_tools
from components.security.encryption.encryption_tools import HashedMessage
from components.security.certification.certificates import EcuCertificate
from tinytree import Tree
from enums.sec_cfg_enum import CAEnum, AsymAuthMechEnum, AuKeyLengthEnum, \
    HashMechEnum

class CA(object):
    '''
    This class resembles a certificate authority
    '''
        
    def __init__(self, next_higher_ca, ca_id, ctf_alg, ctf_alg_key_len, ctf_hash):
        ''' Constructor
        
            Input:    next_higher_ca        CAEnum                CA that is the parent of this CA in the hierarchical CA tree
                      ca_id                 CAEnum                identifier of the current CA
                      ctf_alg               AsymAuthMechEnum      encryption algorithm used by the parent CA to sign this certificate
                      ctf_alg_key_len       AuKeyLengthEnum       encryption key length used by the parent CA to sign this certificate
                      ctf_hash              HashMechEnum          hashing mechanism used by the parent CA to sign this certificate
            Output;   -
        '''
        
        # ca information
        self.next_higher_ca = next_higher_ca  # if None than this is root
        self.ca_id = ca_id
        
        # algorithms, hashing methods for signing
        self.ctf_alg = ctf_alg  # from next higher ca
        self.ctf_alg_option = False  # possible further algorithm options to specify
        self.ctf_hash = ctf_hash  # from next higher ca
        self.ctf_alg_key_len = ctf_alg_key_len  # from next higher ca
       
        # algorithm and hashing method with which this signature is saved (from next higher level)
        self.sig_alg = self.ctf_alg  # if root certificate
        self.sig_hash = self.ctf_hash  # if root certificate
        if self.next_higher_ca != None:
            self.sig_alg = self.next_higher_ca.ctf_alg  # from next higher ca
            self.sig_hash = self.next_higher_ca.ctf_hash  # from next higher ca
           
        # Private and Public key generated with this algorithms        
        self.priv_key, self.pub_key = encryption_tools.asy_get_key_pair(self.ctf_alg, self.ctf_alg_key_len, self.ctf_alg_option)
    
    
    def get_signature(self, req_certificate):
        ''' Create a signature for the next lower CA
            
            Input:     req_certificates    ECUCertificate        the next lower certificate that will be signed by this CA
            Output:    signature           EncryptedMessage      signed version of the passed certificate
                       ctf_alg             AsymAuthMechEnum      encryption algorithm used by this CA to sign this certificate  
                       ctf_hash            HashMechEnum          hashing mechanism used by this CA to sign this certificate
        '''
        signature = encryption_tools.asy_encrypt(HashedMessage(req_certificate, self.ctf_hash), self.priv_key)    
        return signature, self.ctf_alg, self.ctf_hash
    
    
    def request_user_certificate(self, in_version, in_valid_from, in_valid_till, user_id):
        ''' returns a certificate that is signed by this CA
            
            Input:  in_version        float             certificate version
                    in_valid_from     float             start of certificate validity
                    in_valid_till     float             end of certificate validity
                    user_id           string            identifier of the certificate owner
            Output: certificate       ECUCertificate    certificate that was generated
                    priv_key          AsymetricKey      private Key corresponding to the public key of the certificate
        '''
        # request certificate
        certificate = self.request_certificate(in_version, in_valid_from, in_valid_till)
        certificate.user_id = user_id
        
        # return it
        return certificate, self.priv_key
    
    
    def request_certificate(self, in_version, in_valid_from, in_valid_till):
        ''' returns a certificate for the current CA
            
            Input:  in_version        float             certificate version
                    in_valid_from     float             start of certificate validity
                    in_valid_till     float             end of certificate validity                    
            Output: certificate       ECUCertificate    certificate that was generated                    
        '''
        # generate
        certificate = EcuCertificate()
        
        # general information
        certificate.version = in_version
        certificate.valid_from = in_valid_from
        certificate.valid_till = in_valid_till
        
        # information given by next higher CA
        if self.next_higher_ca != None:
            
            # apply for certificate at next higher instance
            certificate.cert_auth = self.next_higher_ca.ca_id
            certificate.signature, certificate.signature_alg, certificate.signature_hash = \
                                            self.next_higher_ca.get_signature(certificate)
        else:
            # Root
            certificate.signature_alg = self.sig_alg
            certificate.signature_hash = self.sig_hash
            certificate.signature, certificate.signature_alg, certificate.signature_hash = self.get_signature(certificate)
            certificate.cert_auth = None  # Its the root
        
        # information about the certificate receiver
        certificate.user_id = self.ca_id
        certificate.pub_k_alg = self.ctf_alg
        certificate.pub_key_user = self.pub_key
        
        return certificate
        
class CANode(Tree):
    ''' 
    This structure is used to depict the structure of
    the CA Hierarchy and resembles one Node in the hierarchy    
    '''
    
    def __init__(self, value=None, children=None):
        ''' Constructor
        
            Input:    value    object    Value that is wrapped
            Output:    -                
        '''
        Tree.__init__(self, children)
        
        self.value = value
        
class CAHierarchy(object):
    '''
    This class resembles a CA Hierarchy. If a certificate is requested
    from any CA within this tree all certificates along the path to the root are
    needed to verify this certificate
    '''
    def __init__(self):
        ''' Constructor
            
            Input:     -
            Output:    -        
        '''
        # initialize information
        self._set_ca_information()
       
    
    def ca_by_id(self, look_id):   
        ''' returns the instance of class CA that corresponds
            to the corresponding identifier look_id within the
            CA Hierarchy
            
            Input:    look_id    string/Enum    identifier for the CA that is requested
            Output:   node       CA             CA object which has the given identifier                   
        ''' 
        
        # found
        if look_id == self.ca_root.value.ca_id:
            return self.ca_root.value
        
        # keep on
        self.current_id = look_id
        node = self.ca_root.findForwards(self._selector_by_id)
        
        # found
        if node != None:
            return node.value
        return node
                
    
    def rebuild_ca_information_default_algs(self, pub_alg, pub_key_len, pub_hash_alg):
        ''' this method generates a standard ca hierarchy within which all
            certificates ose the given encryption algorithm and the given
            hashing mechanism
        
            Input:  pub_alg            AsymAuthMechEnum    encryption algorithm used for signing at all CA nodes
                    pub_key_len        AuKeyLengthEnum     key length used for signing at all CA nodes
                    pub_hash_alg       HashMechEnum        hashing mechanism used for signing at all CA nodes
            Output: -
        '''
        
        # root CA
        root_ca = CA(None, CAEnum.ROOT, pub_alg, pub_key_len, pub_hash_alg)
        self.ca_root = CANode(root_ca)
        
        # layer 1
        ca_1 = CA(root_ca, CAEnum.CA_L1, pub_alg, pub_key_len, pub_hash_alg)
        ca_1_n = CANode(ca_1)
        self.ca_root.addChild(ca_1_n)

        ca_2 = CA(root_ca, CAEnum.CA_L2, pub_alg, pub_key_len, pub_hash_alg)
        ca_2_n = CANode(ca_2)
        self.ca_root.addChild(ca_2_n)
        
        ca_3 = CA(root_ca, CAEnum.CA_L3, pub_alg, pub_key_len, pub_hash_alg)
        ca_3_n = CANode(ca_3)
        self.ca_root.addChild(ca_3_n)

        # layer 2
        ca_11 = CA(ca_1, CAEnum.CA_L11, pub_alg, pub_key_len, pub_hash_alg)
        ca_11_n = CANode(ca_11)
        ca_1_n.addChild(ca_11_n)
        ca_12 = CA(ca_1, CAEnum.CA_L12, pub_alg, pub_key_len, pub_hash_alg)
        ca_12_n = CANode(ca_12)
        ca_1_n.addChild(ca_12_n)           
        ca_13 = CA(ca_1, CAEnum.CA_L13, pub_alg, pub_key_len, pub_hash_alg)
        ca_13_n = CANode(ca_13)
        ca_1_n.addChild(ca_13_n)
        
        ca_21 = CA(ca_2, CAEnum.CA_L21, pub_alg, pub_key_len, pub_hash_alg)
        ca_21_n = CANode(ca_21)
        ca_2_n.addChild(ca_21_n)
        ca_22 = CA(ca_2, CAEnum.CA_L22, pub_alg, pub_key_len, pub_hash_alg)
        ca_22_n = CANode(ca_22)
        ca_2_n.addChild(ca_22_n)        
        ca_23 = CA(ca_2, CAEnum.CA_L23, pub_alg, pub_key_len, pub_hash_alg)
        ca_23_n = CANode(ca_23)
        ca_2_n.addChild(ca_23_n) 
        
        ca_31 = CA(ca_3, CAEnum.CA_L31, pub_alg, pub_key_len, pub_hash_alg)
        ca_31_n = CANode(ca_31)
        ca_3_n.addChild(ca_31_n)
        ca_32 = CA(ca_3, CAEnum.CA_L32, pub_alg, pub_key_len, pub_hash_alg)
        ca_32_n = CANode(ca_32)
        ca_3_n.addChild(ca_32_n)        
        ca_33 = CA(ca_3, CAEnum.CA_L33, pub_alg, pub_key_len, pub_hash_alg)
        ca_33_n = CANode(ca_33)
        ca_3_n.addChild(ca_33_n) 
        
        # layer 3 only at 31
        ca_311 = CA(ca_31, CAEnum.CA_L311, pub_alg, pub_key_len, pub_hash_alg)
        ca_311_n = CANode(ca_311)
        ca_31_n.addChild(ca_311_n) 
        ca_312 = CA(ca_31, CAEnum.CA_L312, pub_alg, pub_key_len, pub_hash_alg)
        ca_312_n = CANode(ca_312)
        ca_31_n.addChild(ca_312_n)   
        ca_313 = CA(ca_31, CAEnum.CA_L313, pub_alg, pub_key_len, pub_hash_alg)
        ca_313_n = CANode(ca_313)
        ca_31_n.addChild(ca_313_n) 
        
    
    def _set_ca_information(self):
        ''' this method generates a standard ca hierarchy within which all
            certificates use the predefined encryption algorithm and the predefined
            hashing mechanism
        
            Input:  -
            Output: -
        '''
        
        # root CA
        root_ca = CA(None, CAEnum.ROOT, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        self.ca_root = CANode(root_ca)
        
        # layer 1
        ca_1 = CA(root_ca, CAEnum.CA_L1, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_1_n = CANode(ca_1)
        self.ca_root.addChild(ca_1_n)

        ca_2 = CA(root_ca, CAEnum.CA_L2, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_2_n = CANode(ca_2)
        self.ca_root.addChild(ca_2_n)
        
        ca_3 = CA(root_ca, CAEnum.CA_L3, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_3_n = CANode(ca_3)
        self.ca_root.addChild(ca_3_n)

        # layer 2
        ca_11 = CA(ca_1, CAEnum.CA_L11, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_11_n = CANode(ca_11)
        ca_1_n.addChild(ca_11_n)
        ca_12 = CA(ca_1, CAEnum.CA_L12, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_12_n = CANode(ca_12)
        ca_1_n.addChild(ca_12_n)           
        ca_13 = CA(ca_1, CAEnum.CA_L13, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_13_n = CANode(ca_13)
        ca_1_n.addChild(ca_13_n)
        
        ca_21 = CA(ca_2, CAEnum.CA_L21, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_21_n = CANode(ca_21)
        ca_2_n.addChild(ca_21_n)
        ca_22 = CA(ca_2, CAEnum.CA_L22, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_22_n = CANode(ca_22)
        ca_2_n.addChild(ca_22_n)        
        ca_23 = CA(ca_2, CAEnum.CA_L23, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_23_n = CANode(ca_23)
        ca_2_n.addChild(ca_23_n) 
        
        ca_31 = CA(ca_3, CAEnum.CA_L31, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_31_n = CANode(ca_31)
        ca_3_n.addChild(ca_31_n)
        ca_32 = CA(ca_3, CAEnum.CA_L32, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_32_n = CANode(ca_32)
        ca_3_n.addChild(ca_32_n)        
        ca_33 = CA(ca_3, CAEnum.CA_L33, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_33_n = CANode(ca_33)
        ca_3_n.addChild(ca_33_n) 
        
        # layer 3 only hanging at 31
        ca_311 = CA(ca_31, CAEnum.CA_L311, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_311_n = CANode(ca_311)
        ca_31_n.addChild(ca_311_n) 
        ca_312 = CA(ca_31, CAEnum.CA_L312, AsymAuthMechEnum.ECC, AuKeyLengthEnum.bit_256, HashMechEnum.MD5)
        ca_312_n = CANode(ca_312)
        ca_31_n.addChild(ca_312_n)   
        ca_313 = CA(ca_31, CAEnum.CA_L313, AsymAuthMechEnum.RSA, AuKeyLengthEnum.bit_2048, HashMechEnum.MD5)
        ca_313_n = CANode(ca_313)
        ca_31_n.addChild(ca_313_n) 
        
    
    def _selector_by_id(self, node):
        ''' specifies the condition when the search
            has found a match
            
            Input:    node    object     current node to be checked
            Output:   bool    boolean    true if node is a match
            
        '''
        if node.value.ca_id == self.current_id:        
            return True
        return False
