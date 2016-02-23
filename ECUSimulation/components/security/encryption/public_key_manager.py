from tools.singleton import Singleton

class PublicKeyManager(Singleton):
    ''' 
    This class holds all public keys that are passed to it.
    So all public keys that are available can be requested here 
    '''
    
    def __init__(self):
        ''' Constructor
            
            Input:     -
            Output:    -
        ''' 
        self.pub_key = {}
        
    
    def add_key(self, k_id, key):        
        ''' adds a new key to be stored under the given id k_id by this manager
            the same key can be then requested using this id.
            
            Input:      k_id    string/number                id that is used to request the key
                        key     AsymetricKey/SymmetricKey    key that is to be stored
            Output:    -
        '''
        self.pub_key[k_id] = key
        
    def get_key(self, k_id):
        ''' returns the key that was stored under the id
            k_id.
            
            Input:    k_id    string/number                id that is used to request the key
            Output:   key     AsymetricKey/SymmetricKey    stored key
        '''
        try:
            ret = self.pub_key[k_id]
        except:
            ret = None
        return ret
