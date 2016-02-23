'''
Created on 5 May, 2015

@author: artur.mrowca
'''
from tools.singleton import Singleton
from tools.ecu_logging import ECULogger as L
from config.timing_registration import call
import importlib
import subprocess
import time
import csv

class General(Singleton):
    '''
    often used methods are collected here
    '''
    def __init__(self):
        self.used_timeouts = {}
        self.noted_sizes = {}
        self.noted_ts = {}
        
        self.diabled_buffer_control = False
        self.disable_permanent_request = False
        self.disable_fallback_message = True
        
        self.send_only_to_receivers = False
        self.sender_receiver_map = {}  # key: sender_id value: dict: key: stream_id value: list_receivers 
        
        self.csv_writer = False
        self._tags_to_write = False
        
    
        
    def init_csv_writer(self, filepath, tags_to_write):
        
        self.csv_writer = csv.writer(open(filepath, 'w'), delimiter=';')
        self._tags_to_write = tags_to_write
        self.csv_writer.writerow(["time", "ECU ID", "Asc ECU ID", "Tag", "Message ID", "Message Size", "Stream ID", "UID", "Message", "Data"])
        
    def print_subversion_info(self, args):

        outs = "\n"
        for arg in args.__dict__:
            val = args.__dict__[arg] 
            if val != None and val:
                outs += "arg: %s, value: %s\n" % (arg, val)
        
        print("\nStarted with args: %s" % outs)
        
        output = ("\nStarttime: %s\ndate: %s\n" % (time.strftime("%I:%M:%S"), time.strftime("%d/%m/%Y")))
        lProcess = subprocess.Popen(["hg", "summary"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        nextt = lProcess.stdout.readline()
        while nextt:        
            output += str(nextt)
            output += "\n"
            nextt = lProcess.stdout.readline()
            
        output = output.replace("b'", "")
        output = output.replace("\n'", "")
        output = output.replace(" changeset:", "changeset:")
        print("Revision Info: %s" % output)
    
    
    def fill_keys(self, in_dict, ky_lst, fill_val):
        ''' checks if every key in ky_lst is existent.
            If not the value is set with fill_val'''
        try:
            for ky in ky_lst:
                if ky not in in_dict.keys():
                    in_dict[ky] = fill_val
            return in_dict
        except:
            return {}
         
    def fill_keys_2(self, in_dict, ky_lst, fill_val):
        ''' checks if every key in ky_lst is existent.
            If not the value is set with fill_val
            
            only for 2 level dicts[a][b]
            '''
        try:
            for kky in in_dict.keys():
                for ky in ky_lst:
                    if ky not in in_dict[kky].keys():
                        in_dict[kky][ky] = fill_val       
            return in_dict
        except:
            return {}
    
    
    def mon(self, monitor_lst, monitor_input):
        if self.csv_writer:
            if self._tags_to_write and monitor_input.tag not in self._tags_to_write: return
                            
            el = [monitor_input.time_called, str(monitor_input.mon_id), str(monitor_input.asc_id), str(monitor_input.tag), monitor_input.msg_id, monitor_input.msg_size, monitor_input.stream_id, str(monitor_input.unique_id), str(monitor_input.message), str(monitor_input.data)]
            self.csv_writer.writerow(el)
        else:            
            if monitor_input not in monitor_lst.get(): 
                self.surround_cls(monitor_lst, 'append', monitor_input, True)       
    
    
    def note_sz(self, in_key, in_val):
        return
        self.noted_sizes[in_key] = in_val    
        
        
    def note_t(self, in_key, in_val):
        self.noted_ts[in_key] = in_val   
        
    
    def do_try(self, obj, func_name, *args):
        try:
            res = None
            exc_str = "res = obj." + func_name + "(*args)"
            exec(exc_str)
            return res
        except:
            return None

    
    def access_list(self, lst, idx, rep=None):        
        try:
            val = lst[idx]
        except:
            val = -1
            
        if val == None: 
            if rep != None: return ""
            return -1
        return val

     
    def call_or_const(self, in_var, *args):
        
        # static method call
        if isinstance(in_var, list):
            try:
                lst = in_var[0].split('.')
                le = in_var[0][:-len(lst[-1]) - 1]                
                impo = importlib.import_module(le)                    
                obj = impo.__dict__[lst[-1]]()  # @UnusedVariable
                func_name = in_var[1]
                val = None
                val = eval("obj." + func_name + "(*args)")
                return val
            except:
                pass
#                 ECULogger().log_traceback()
        
        # simple method call
        if not isinstance(in_var, (int, float, complex)):
            out_val = call(in_var, *args)
        
        # const variable call
        else:
            out_val = in_var
            
        return out_val
    
    
    def dict_exists(self, in_dict, in_key):
        try:
            in_dict[in_key]
            if in_dict[in_key]:
                return True
        except:
            pass
        return False
    
    
    def add_to_three_dict(self, in_dict, ky1, ky2, val):
        try:
            in_dict[ky1]
        except:
            in_dict[ky1] = {}
        
        in_dict[ky1][ky2] = val

    def four_dict_exists(self, in_dict, ky1, ky2, ky3):
        try:
            in_dict[ky1][ky2][ky3]
            return True
        except:
            return False

    
    def add_to_four_dict(self, in_dict, ky1, ky2, ky3, val):
        try:
            in_dict[ky1]
        except:
            in_dict[ky1] = {}
        try:
            in_dict[ky1][ky2]
        except:
            in_dict[ky1][ky2] = {}
            
        in_dict[ky1][ky2][ky3] = val
        
    def five_dict_exists(self, in_dict, ky1, ky2, ky3, ky4):
        try:
            in_dict[ky1][ky2][ky3][ky4]
            return True
        except:
            return False

    
    def add_to_five_dict(self, in_dict, ky1, ky2, ky3, ky4, val):
        try:
            in_dict[ky1]
        except:
            in_dict[ky1] = {}
        try:
            in_dict[ky1][ky2]
        except:
            in_dict[ky1][ky2] = {}
        try:
            in_dict[ky1][ky2][ky3]
        except:
            in_dict[ky1][ky2][ky3] = {}
            
        in_dict[ky1][ky2][ky3][ky4] = val
        
    
    
    
    def dictlist_exists(self, dict_list, in_key):
        ''' returns True if the dict_list element 
            has entries and False if it is empty or
            if the key does not exist'''
        try:
            da_lst = dict_list[in_key]
            if da_lst:
                return True
        except:
            pass
        return False
        
        
    def force_add_dict_list(self, in_dict, in_key, in_val, max_lst_len=None):
        ''' adds an element to the dictionary. If the element 
            has no list it will be created '''
        try:
            in_dict[in_key].append(in_val)
        except:
            in_dict[in_key] = [in_val]
            
        if max_lst_len != None:
            if len(in_dict[in_key]) > max_lst_len:
                in_dict[in_key] = in_dict[in_key][-(max_lst_len - 1):]
    
    
     
    def force_add_dict_list_2(self, in_dict, in_key, in_key_2, in_val, max_lst_len=None):
        ''' adds an element to the dictionary. If the element 
            has no list it will be created '''
        try:
            in_dict[in_key]
        except:
            in_dict[in_key] = {}
        try:
            in_dict[in_key][in_key_2].append(in_val)
        except:
            in_dict[in_key][in_key_2] = [in_val]
            
        if max_lst_len != None:
            if len(in_dict[in_key][in_key_2]) > max_lst_len:
                in_dict[in_key][in_key_2] = in_dict[in_key][in_key_2][-(max_lst_len - 1):]
                       
    
    def to(self, sim_env, timeout_val, var_name, class_name, caller_id=None):
        ''' Logs a certain value to the debug output while at the
            same time timing out for the duration of the variable value'''
        L().log(2, var_name, class_name, timeout_val)
        
        if caller_id != None:
            self.add_to_three_dict(self.used_timeouts, caller_id, str([class_name, var_name]), timeout_val)
        yield sim_env.timeout(timeout_val)
      
    def to_t(self, sim_env, timeout_val, var_name, class_name, caller_id=None):
        ''' Logs a certain value to the debug output  '''
        L().log(2, var_name, class_name, timeout_val)
        return
        if caller_id != None:
            self.add_to_three_dict(self.used_timeouts, caller_id, str([class_name, var_name]), timeout_val)
        
      
    
    def surround(self, func, show, *args):
        try:
            func(*args)
        except:
            if show:
                L().log_traceback()
           
         
    def surround_cls(self, cls, func, arg, show):
        show = False
        try:
            exc_str = "cls.%s(arg)" % func
            exec(exc_str)
        except:
            if show:
                L().log_traceback()
        
    
    def val_log_info(self, val, log1, *args):
        L().log(log1, *args)
        return val
    
class Wrap(object):
    '''wraps any object to be a reference'''
    
    def __init__(self):
        self._content = None
    
    def set(self, val):
        self._content = val
        
    def get(self):
        return self._content
    
class RefList(object):
    ''' list that can be passed by reference'''
    
    def __init__(self):
        self._content = []
        self._clear_on_next = False

    def join(self, lst):
        self._content += lst

    def append(self, elem):
        if self._clear_on_next:
            self._content = []   
            self._clear_on_next = False     
        self._content.append(elem)
        
    def isempty(self):
        return not self._content
        
    def clear_on_access(self):
        self._clear_on_next = True
        
    def clear(self):
        self._content = []
        
    def get(self):
        return self._content
    
    def __len__(self):
        return len(self._content)
    
