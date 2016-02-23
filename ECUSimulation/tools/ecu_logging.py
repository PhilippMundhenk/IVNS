'''
Created on 5 May, 2015

@author: artur.mrowca
'''
from tools.singleton import Singleton
from config.strings import log_strings as s
from config.strings import log_errors as e
import logging
import traceback
import sys
import inspect
from functools import wraps
# from tools.performance_evaluator import PerformanceEval

def log_to_str(v):
    if isinstance(v, str):
        return ["'", v.replace('\n', '\\n'), "'"].join('')
    else:
        try:return str(v).replace('\n', '\\n')
        except: return '<ERROR: CANNOT PRINT>'

def format_ex(e):
    out_str = ""
    out_str += 'Exception thrown, %s: %s\n' % (type(e), str(e))
    frames = inspect.getinnerframes(sys.exc_info()[2])
    for frame_info in reversed(frames):
        f_locals = frame_info[0].f_locals
        if '__lgw_marker_local__' in f_locals:
            continue        
        # log the frame information
        out_str += ('  File "%s", line %i, in %s\n    %s\n' % (frame_info[1], frame_info[2], frame_info[3], frame_info[4][0].lstrip()))
        # log every local variable of the frame
        for k, v in f_locals.items():
            try: out_str += ('    %s = %s\n' % (k, log_to_str(v)))
            except: pass                
    return out_str

def try_ex(fn):
    
    @wraps(fn)
    def wrapped(*args, **kwargs):
        try:       
            return fn(*args, **kwargs)
        except Exception as e:       
            try:
                ky = fn.__qualname__.split(".")[0]
                cls = fn.__globals__[ky]
                ECULogger().log_err(401, cls)
            except:
                print(format_ex(e))
                ECULogger().log_err(401, fn.__qualname__)
            # logging.error(format_ex(e))
            ECULogger().log_traceback()    
            
    return wrapped

class ECULogger(Singleton):
    
    def __init__(self):
        self.show_output = True
        self.enabled = False
    
    def log(self, idx, *args):
        if not self.enabled: return
        if s.log_dict[idx][2] == logging.INFO:
            self.log_info(idx, *args)
            
        if s.log_dict[idx][2] == logging.WARN:
            self.log_warn(idx, *args)
            
        if s.log_dict[idx][2] == logging.DEBUG:
            self.log_debug(idx, *args)
    
    def log_err(self, idx, *args):
        if not self.enabled: return
        try:
            self._log(e.log_dict, logging.error, idx, args)
        except:
            traceback.print_exc()
    
    def log_debug(self, idx, *args):
        if not self.enabled: return
        try:
            self._log(s.log_dict, logging.debug, idx, args)
        except:
            traceback.print_exc()
     
    def log_info(self, idx, *args):
        if not self.enabled: return
        try:
            self._log(s.log_dict, logging.info, idx, args)
        except:
            traceback.print_exc()
         
    def log_warn(self, idx, *args):
        if not self.enabled: return
        try:
            self._log(s.log_dict, logging.warn, idx, args)
        except:
            traceback.print_exc()
    
    def log_info_traceback(self, idx, *args):
        if not self.enabled: return
        try:
            self.log_info(idx, args)
            self.log_traceback()
        except:
            traceback.print_exc()
        
    def log_traceback(self):
        if not self.enabled: return
        try:
            logging.error(traceback.format_exc())
        except:
            traceback.print_exc()
    
    def show_outputf(self, show_output):
        self.show_output = show_output
    
    def _log(self, dic, func, idx, args):
        try:
            da_str = dic[idx][0]  # String to show
            show = dic[idx][1]  # show this logging True or false
            
            if show and self.show_output:
                if not args:
                    func(da_str)
                else:
                    func(da_str % args)
        except:
            logging.error('Logging Error at Dict index %s: %s' % (idx, traceback.format_exc()))     
        
        
        
        
        
        

