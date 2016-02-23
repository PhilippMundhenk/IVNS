'''
Created on 29 May, 2015

Under construction

@author: artur.mrowca
'''
import pickle
import uuid
import inspect
import simpy.resources.store
from components.security.encryption.public_key_manager import PublicKeyManager


class ECUPickler(pickle.Pickler):
    '''
    This class is used to save and load environments
    '''
    simpy_envs = {}    
    rel_instances = {''}
    
    def persistent_id(self, obj):
        # Instead of pickling MemoRecord as a regular class instance, we emit a
        # persistent ID.
        
        if obj.__class__.__name__ == 'generator':
            # save the function name and the object that holds this function            
            det = inspect.getgeneratorlocals(obj)
            inst = det['self']
            func_name = obj.__name__
            args_dict = det

#             print ('!!!!!!SAVE: INSTANZ: %s // GENERATOR: %s' % (inst, obj))
                
            return (obj.__class__.__name__, inst, func_name, args_dict)

        if isinstance(object, PublicKeyManager):
            try:
                ky = ECUPickler.simpy_envs[str(obj)]
            except:
                ECUPickler.simpy_envs[str(obj)] = 'simpy.Environment' + str(uuid.uuid4())
                ky = ECUPickler.simpy_envs[str(obj)]
            return ("simpy.Environment", ky)
        
        if isinstance(obj, simpy.Environment):
            # Here, our persistent ID is simply a tuple, containing a tag and a
            # key, which refers to a specific record in the database.
            try:
                ky = ECUPickler.simpy_envs[str(obj)]
            except:
                ECUPickler.simpy_envs[str(obj)] = 'simpy.Environment' + str(uuid.uuid4())
                ky = ECUPickler.simpy_envs[str(obj)]
            return ("simpy.Environment", ky)
        
        elif isinstance(obj, simpy.resources.store.Store):  # simpy.Store(self.sim_env, capacity=1) 
            try:
                ky = ECUPickler.simpy_envs[str(obj)]
            except:
                ECUPickler.simpy_envs[str(obj)] = 'simpy.resources.store.Store' + str(uuid.uuid4())
                ky = ECUPickler.simpy_envs[str(obj)]
            
            try:
                env_key = ECUPickler.simpy_envs[str(obj._env)]        
            except:
                ECUPickler.simpy_envs[str(obj)] = 'simpy.Environment' + str(uuid.uuid4())
                env_key = ECUPickler.simpy_envs[str(obj)]                        
            return ("simpy.resources.store.Store", ky, env_key, obj.capacity)
            
            
        else:
            # If obj does not have a persistent ID, return None. This means obj
            # needs to be pickled as usual.
            return None



class ECUUnpickler(pickle.Unpickler):
    simpy_envs = {}
    
    def __init__(self, file):
        super().__init__(file)

    def persistent_load(self, pid):
        # This method is invoked whenever a persistent ID is encountered.
        # Here, pid is the tuple returned by DBPickler.
        
        if pid[0] == 'generator':
            # Problem generator wird beim laden nicht fuer dasselbe objekt gespeichert wie es geladen wird
                    
            # save the function name and the object that holds this function
            inst = pid[1]
            func_name = pid[2]
            args_dict = pid[3]
            arg_str = ""
            for ky in args_dict:
                if ky == 'self':
                    continue
                arg_str += ky
                arg_str += "="
                arg_str += "args_dict['" + ky + "']"
                arg_str += ","
            try:
                if arg_str[-1] == ",": arg_str = arg_str[:-1]
            except:
                pass
            exc_str = "inst." + func_name + "(" + arg_str + ")"            
            val = eval(exc_str)        
        
            
#             print ('!!!!!!LOAD: INSTANZ: %s // GENERATOR: %s' % (inst, val))
            
            return val
        
        if pid[0] == "simpy.Environment":  # fuer alle unpickelbaren einfachen Objekte laueft das!
            try:
                obj = ECUUnpickler.simpy_envs[pid[1]]
            except:
                ECUUnpickler.simpy_envs[pid[1]] = simpy.Environment()
                obj = ECUUnpickler.simpy_envs[pid[1]]   
            return obj
        
        elif pid[0] == "simpy.resources.store.Store":  # fuer alle unpickelbaren einfachen Objekte laueft das!
            try:
                obj = ECUUnpickler.simpy_envs[pid[1]]
            except:
                env_key = pid[2]                
                try:
                    env = ECUUnpickler.simpy_envs[env_key]
                except:
                    ECUUnpickler.simpy_envs[env_key] = simpy.Environment()
                    env = ECUUnpickler.simpy_envs[env_key]    
                capacity = pid[3]
                
                ECUUnpickler.simpy_envs[pid[1]] = simpy.resources.store.Store(env, capacity)
                obj = ECUUnpickler.simpy_envs[pid[1]]   
                
            return obj

        else:
            # Always raises an error if you cannot return the correct object.
            # Otherwise, the unpickler will think None is the object referenced
            # by the persistent ID.
            raise pickle.UnpicklingError("unsupported persistent object")
        

