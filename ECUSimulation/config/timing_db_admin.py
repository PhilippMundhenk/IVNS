from xml.etree.cElementTree import ElementTree as ET
import sqlite3 as lite
from enums.gen_cfg_enums import IniConfig  # @UnusedWildImport # Leave that as it is!
from enums.sec_cfg_enum import *  # @UnusedWildImport # Leave that as it is!
import logging
import os
from scipy.interpolate import interp1d
import sqlite3
from tools.ecu_logging import ECULogger
from time import sleep

class TimingDBMap(Singleton):
    ''' holds the measurements Database and offers methods
        to extract values from it '''

    def __init__(self):
        ''' constructor
            
            Input:   -
            Output:  -
        '''
        self._load_init(os.path.join(os.path.dirname(__file__), "data/timingMapping.xml"), "data/measurements.db")
        self.tns = "{http://www.tum-create.edu.sg/timingSchema}"
        self._already_requested = {}
        self.enable_fallback_message = False
        self._fallback_libs = ['Crypto_Lib_HW', 'Crypto_Lib_SW', 'CyaSSL']
        self._fallbacks = self._init_fallbacks()
    
    def _load_init(self, filepath, db_path):
        self.root = ET.parse(self, source=filepath)
        con = lite.connect(os.path.join(os.path.dirname(__file__), db_path))
        self.db = con.cursor()
        self.db.execute('''PRAGMA journal_mode = OFF''')
        con.commit()

    def _init_fallbacks(self):
        ''' this method defines fallbacks for certain lookup requests. It defines
            which values should be used instead
            
            Input    -
            Output:  fallbacks    dict        dictionary key: [lib, mode, alg, alg_mode, keylen, exp, param_len] 
                                              value [lib, mode, alg, alg_mode, keylen, exp, param_len] to use
        '''
        fallbacks = {}
        

        
        
        ky = str(['CyaSSL', 'ENCRYPTION', 'RSA', False, 2048, 3, False])
        fallbacks[ky] = ['CyaSSL', 'ENCRYPTION', 'RSA', False, 1024, 3, False]
        
        ky = str(['Crypto_Lib_SW', 'VERIFY', 'RSA', False, 512, 3, False])
        fallbacks[ky] = ["Crypto_Lib_SW", "VERIFY", "RSA", False, 512, 5, False]
        
        ky = str(['Crypto_Lib_SW', 'SIGN', 'RSA', False, 512, 3, False])
        fallbacks[ky] = ["Crypto_Lib_SW", "SIGN", "RSA", False, 512, 5, False]
        
        ky = str(['Crypto_Lib_HW', 'SIGN', 'RSA', False, 512, 3, False])
        fallbacks[ky] = ["Crypto_Lib_SW", "SIGN", "RSA", False, 512, 5, False]
        
        ky = str(['CyaSSL', 'ENCRYPTION', 'RSA', False, 2048, 5, False])
        fallbacks[ky] = ['CyaSSL', 'ENCRYPTION', 'RSA', False, 1024, 5, False]
        
        ky = str(['CyaSSL', 'ENCRYPTION', 'RSA', False, 2048, 17, False])
        fallbacks[ky] = ['CyaSSL', 'ENCRYPTION', 'RSA', False, 1024, 17, False]
        
        ky = str(['CyaSSL', 'ENCRYPTION', 'RSA', False, 2048, 257, False])
        fallbacks[ky] = ['CyaSSL', 'ENCRYPTION', 'RSA', False, 1024, 257, False]
        
        ky = str(["Crypto_Lib_SW", "ENCRYPTION", "RSA", False, 2048, 3, False])
        fallbacks[ky] = ["CyaSSL", "ENCRYPTION", "RSA", False, 1024, 3, False]
        
        ky = str(['Crypto_Lib_SW', 'ENCRYPTION', 'RSA', False, 2048, 5, False])
        fallbacks[ky] = ["CyaSSL", "ENCRYPTION", "RSA", False, 1024, 5, False]
        
        ky = str(['Crypto_Lib_SW', 'ENCRYPTION', 'RSA', False, 2048, 17, False])
        fallbacks[ky] = ["CyaSSL", "ENCRYPTION", "RSA", False, 1024, 17, False]
        
        ky = str(['Crypto_Lib_SW', 'ENCRYPTION', 'RSA', False, 2048, 257, False])
        fallbacks[ky] = ["CyaSSL", "ENCRYPTION", "RSA", False, 1024, 257, False]
        
        ky = "['Crypto_Lib_SW', 'DECRYPTION', 'RSA', False, 2048, 3, False]"
        fallbacks[ky] = ["CyaSSL", "DECRYPTION", "RSA", False, 1024, 3, False]
        
        ky = str(['CyaSSL', 'DECRYPTION', 'RSA', False, 2048, 3, False])
        fallbacks[ky] = ['CyaSSL', 'DECRYPTION', 'RSA', False, 1024, 3, False]
        
        ky = str(['CyaSSL', 'DECRYPTION', 'RSA', False, 2048, 5, False])
        fallbacks[ky] = ['CyaSSL', 'DECRYPTION', 'RSA', False, 1024, 5, False]
        
        ky = str(['CyaSSL', 'DECRYPTION', 'RSA', False, 2048, 17, False])
        fallbacks[ky] = ['CyaSSL', 'DECRYPTION', 'RSA', False, 1024, 17, False]
        
        ky = str(['CyaSSL', 'DECRYPTION', 'RSA', False, 2048, 257, False])
        fallbacks[ky] = ['CyaSSL', 'DECRYPTION', 'RSA', False, 1024, 257, False]
        
        ky = "['Crypto_Lib_SW', 'DECRYPTION', 'RSA', False, 2048, 5, False]"
        fallbacks[ky] = ["CyaSSL", "DECRYPTION", "RSA", False, 1024, 5, False]
        
        ky = "['Crypto_Lib_SW', 'DECRYPTION', 'RSA', False, 2048, 17, False]"
        fallbacks[ky] = ["CyaSSL", "DECRYPTION", "RSA", False, 1024, 17, False]
        
        ky = "['Crypto_Lib_SW', 'DECRYPTION', 'RSA', False, 2048, 257, False]"
        fallbacks[ky] = ["CyaSSL", "DECRYPTION", "RSA", False, 1024, 257, False]   
        
        ky = "['Crypto_Lib_SW', 'VERIFY', 'RSA', False, 2048, 3, False]"
        fallbacks[ky] = ["Crypto_Lib_SW", "VERIFY", "RSA", False, 2048, 5, False]
        
        ky = str(['Crypto_Lib_HW', 'VERIFY', 'RSA', False, 512, 3, False])
        fallbacks[ky] = ["Crypto_Lib_SW", "VERIFY", "RSA", False, 512, 5, False]
        
        ky = "['Crypto_Lib_SW', 'SIGN', 'RSA', False, 2048, 3, False]"
        fallbacks[ky] = ["Crypto_Lib_SW", "SIGN", "RSA", False, 2048, 5, False]
        
        ky = str(['Crypto_Lib_SW', 'VERIFY', 'RSA', False, 1024, 3, False])
        fallbacks[ky] = ["Crypto_Lib_SW", "VERIFY", "RSA", False, 1024, 5, False]
        
        ky = str(['Crypto_Lib_SW', 'SIGN', 'RSA', False, 1024, 3, False])
        fallbacks[ky] = ["Crypto_Lib_SW", "SIGN", "RSA", False, 1024, 5, False]
        
        ky = str(["Crypto_Lib_HW", "ENCRYPTION", "RSA", False, 2048, 3, False])
        fallbacks[ky] = ["CyaSSL", "ENCRYPTION", "RSA", False, 1024, 3, False]
        
        ky = str(['Crypto_Lib_HW', 'ENCRYPTION', 'RSA', False, 2048, 5, False])
        fallbacks[ky] = ["CyaSSL", "ENCRYPTION", "RSA", False, 1024, 5, False]
        
        ky = str(['Crypto_Lib_HW', 'ENCRYPTION', 'RSA', False, 2048, 17, False])
        fallbacks[ky] = ["CyaSSL", "ENCRYPTION", "RSA", False, 1024, 17, False]
        
        ky = str(['Crypto_Lib_HW', 'ENCRYPTION', 'RSA', False, 2048, 257, False])
        fallbacks[ky] = ["CyaSSL", "ENCRYPTION", "RSA", False, 1024, 257, False]
        
        ky = "['Crypto_Lib_HW', 'DECRYPTION', 'RSA', False, 2048, 3, False]"
        fallbacks[ky] = ["CyaSSL", "DECRYPTION", "RSA", False, 1024, 3, False]
        
        ky = "['Crypto_Lib_HW', 'DECRYPTION', 'RSA', False, 2048, 5, False]"
        fallbacks[ky] = ["CyaSSL", "DECRYPTION", "RSA", False, 1024, 5, False]
        
        ky = "['Crypto_Lib_HW', 'DECRYPTION', 'RSA', False, 2048, 17, False]"
        fallbacks[ky] = ["CyaSSL", "DECRYPTION", "RSA", False, 1024, 17, False]
        
        ky = "['Crypto_Lib_HW', 'DECRYPTION', 'RSA', False, 2048, 257, False]"
        fallbacks[ky] = ["CyaSSL", "DECRYPTION", "RSA", False, 1024, 257, False]   
        
        ky = "['Crypto_Lib_HW', 'VERIFY', 'RSA', False, 2048, 3, False]"
        fallbacks[ky] = ["Crypto_Lib_SW", "VERIFY", "RSA", False, 2048, 5, False]
        
        ky = "['Crypto_Lib_HW', 'SIGN', 'RSA', False, 2048, 3, False]"
        fallbacks[ky] = ["Crypto_Lib_SW", "SIGN", "RSA", False, 2048, 5, False]
        
        ky = str(['Crypto_Lib_HW', 'VERIFY', 'RSA', False, 1024, 3, False])
        fallbacks[ky] = ["Crypto_Lib_SW", "VERIFY", "RSA", False, 1024, 5, False]
        
        ky = str(['Crypto_Lib_HW', 'SIGN', 'RSA', False, 1024, 3, False])
        fallbacks[ky] = ["Crypto_Lib_SW", "SIGN", "RSA", False, 1024, 5, False]
        
        
        
        
        return fallbacks
        
        
    
    def lookup(self, lib=False, mode=False, alg=False, alg_mode=False, keylen=False, exp=False, param_len=False, data_size=False, ret_all=False):
        ''' looks for a time value in the database if none found returns none
        Library:    Crypto_Lib_SW, Crypto_Lib_HW, CyaSSL
        Input is Matlab style: var_name, var_value, var_name, var_value, ...        
        Library TEXT, Mode TEXT, Algorithm TEXT, AlgorithmMode TEXT, Keylength INT, Exponent INT, Parameterlength INT, Datasize INT, Time DOUBLE
        
        Input:  lib        string            value of library column in the DB
                mode       string            mode requested of library column in the DB e.g. ENCRYPTION, DECRYPTION,...
                alg        string            name of the algorithm of library column in the DB
                alg_mode   string            name of algorithm mode of library column in the DB (e.g. CTR, ...)
                keylen     integer           length of the key in bit of library column in the DB
                exp        integer           size of the exponent when RSA is used
                param_len  integer           length of the parameter whenn ECC is used (library column in the DB )
                data_size  integer           size of the data of library column in the DB
                ret_all    boolean           if this value is true the values for all data_sizes will be returned
        Output: time       float             time that was requested in the data base given above input values        
        '''
#         print("ACCESS DATABASE")
        
        try:
            # build expression
            exc_str = 'SELECT * FROM Measurements WHERE '
            exc_str_b = exc_str
            if lib: exc_str = exc_str + "Library = '" + lib + "' AND "
            if mode: exc_str = exc_str + "Mode = '" + mode + "' AND "
            if alg: exc_str = exc_str + "Algorithm = '" + alg + "' AND "
            if alg_mode: exc_str = exc_str + "AlgorithmMode = '" + alg_mode + "' AND "
            if keylen: exc_str = exc_str + "Keylength = " + str(keylen) + " AND "
            if exp: exc_str = exc_str + "Exponent = " + str(exp) + " AND "
            if param_len: exc_str = exc_str + "Parameterlength = " + str(param_len) + " AND "
            if data_size: exc_str = exc_str + "Datasize = " + str(data_size) + " AND "
            exc_str = exc_str[:-4]
            
            # validate expression
            if exc_str_b != exc_str:
                ioerror = True
                cnt = 0
                while ioerror:
                    try:
                        self.db.execute(exc_str)
                        ioerror = False
                    except sqlite3.OperationalError:
                        cnt = cnt + 1
                        # logging.warn("\tERROR: Database problem. Waiting shortly and trying again")
                        sleep(1)
                        ioerror = True
                        # if cnt > 10:
                        #    logging.warn("\tERROR: Database problem could not be resolved...")
                            
            # receive data
            data = self.db.fetchall()
            
            # check return all selected
            if data and ret_all:
                return data
            elif data:
                return data[0][-1]
            else:
                return None
        except sqlite3.ProgrammingError:
            self._load_init(os.path.join(os.path.dirname(__file__), "data/timingMapping.xml"), "data/measurements.db")
            return self.lookup(lib, mode, alg, alg_mode, keylen, exp, param_len, data_size, ret_all)
        except:
            ECULogger().log_traceback()
            return None

    
    def lookup_interpol(self, lib=False, mode=False, alg=False, alg_mode=False, keylen=False, exp=False, param_len=False, data_size=False, description=False):
        ''' looks for a value in the database. If none is found looks for variables 
            around it and tries to interpolate a value from the neighboring values
        
            Input:  lib        string            value of library column in the DB
                    mode       string            mode requested of library column in the DB e.g. ENCRYPTION, DECRYPTION,...
                    alg        string            name of the algorithm of library column in the DB
                    alg_mode   string            name of algorithm mode of library column in the DB (e.g. CTR, ...)
                    keylen     integer           length of the key in bit of library column in the DB
                    exp        integer           size of the exponent when RSA is used
                    param_len  integer           length of the parameter whenn ECC is used (library column in the DB )
                    data_size  integer           size of the data of library column in the DB
                    ret_all    boolean           if this value is true the values for all data_sizes will be returned
            Output: time       float             interpolated time from requested values in the database 
        '''

        try:
            return self._already_requested[str([lib, mode, alg, alg_mode, keylen, exp, param_len, data_size])]
        except: 
            pass
        # fallback in either direction
        if lib == "CyaSSL": fallback_libs = self._fallback_libs[::-1] 
        else: fallback_libs = self._fallback_libs
        
        # check input format
        if isinstance(data_size, list):
            return None
        
        # try getting result directly
        result = self.lookup(lib=lib, mode=mode, alg=alg, alg_mode=alg_mode, keylen=keylen, exp=exp, \
                          param_len=param_len, data_size=data_size)
                
        if result != None: 
            self._already_requested[str([lib, mode, alg, alg_mode, keylen, exp, param_len, data_size])] = float(result)
            return float(result)
            
        # get results for all data sizes
        result = self.lookup(lib=lib, mode=mode, alg=alg, alg_mode=alg_mode, keylen=keylen, exp=exp, \
                          param_len=param_len, ret_all=True)        
        
        # if nothing found use fallback value
        lib_pos = fallback_libs.index(lib)
        while result == None:   
            lib_pos += 1         
            if lib_pos == len(fallback_libs): 
                
                # if ecc try to use fallback param lengths
                if alg == "ECC":
                    result = self.lookup(lib="CyaSSL", mode=mode, alg=alg, alg_mode=alg_mode, keylen=keylen, exp=exp, param_len=384, ret_all=True)                     
                    if TimingDBMap().enable_fallback_message and result != None: print("using fallback  parameter length 384 and CyaSSL for %s" % description)
                    break 
                
                # exponent problem
                if str([lib, mode, alg, alg_mode, keylen, exp, param_len]) in self._fallbacks.keys():
                    request_tuple = self._fallbacks[str([lib, mode, alg, alg_mode, keylen, exp, param_len])]
                    result = self.lookup(lib=request_tuple[0], mode=request_tuple[1], alg=request_tuple[2], alg_mode=request_tuple[3], keylen=request_tuple[4], exp=request_tuple[5], param_len=request_tuple[6], ret_all=True)                     
                    if TimingDBMap().enable_fallback_message and result != None: print("using fallback  %s  for %s" % (str(request_tuple), description))
                    break  
                print("ERROR: Returning None - Please define in TimingDBMap()._init_fallbacks a fallback value for %s" % str([lib, mode, alg, alg_mode, keylen, exp, param_len])) 
                return None
            
            result = self.lookup(lib=fallback_libs[lib_pos], mode=mode, alg=alg, alg_mode=alg_mode, keylen=keylen, exp=exp, \
                          param_len=param_len, ret_all=True)
            
            if result != None: 
                if self.enable_fallback_message:
                    print("%s: Used fallback entry of library %s for request: %s" % (description, fallback_libs[lib_pos], str([alg, alg_mode, keylen, exp, param_len])))
                break
                

        # cubic interpolation curve to determine value
        result.sort(key=lambda x: x[-2])  
        if len(result) > 500:
            result = result[:500]
        result.sort(key=lambda x: x[-2])        
        x = [k[-2] for k in result] 
        y = [k[-1] for k in result]         
        if x[0] != 1:
            x = [1] + x
            y = [0] + y         
        
        # try cubic interpolation
        try: f = interp1d(x, y, kind='cubic') 
        except: f = interp1d(x, y, kind='linear') 
        
        try:       
            time_found = f(data_size)
        except:
            time_found = self._extended_line(data_size, x, y)  # create a line that is connected by two points  
            
        if time_found < 0:
            logging.warn("%s: Interpolation found negative number use 0.000001 instead" % (description))
            time_found = 0.000001
            
        self._already_requested[str([lib, mode, alg, alg_mode, keylen, exp, param_len, data_size])] = float(time_found)
        return float(time_found)

    
    def lookup_time(self, class_name, var_name, variant, proj_vars):
        
        ''' 1. Get dbSpec Nodes'''
        time_map_node = self._get_timing_mapping(class_name, var_name)
        lst_db_spec = self._get_db_lookup_spec(time_map_node, variant)
        if not lst_db_spec: return None        
        
        for db_spec in lst_db_spec:

            ''' 2. check if all conditions specified in timingMapping.xml are fulfilled '''
            lookup = self._lookup_by_id(db_spec.attrib["lookupid"]) 
            conditions = self._get_conds_from_spec(db_spec)        
            conds_fulfilled = self._check_conditions(conditions, proj_vars)
              
            ''' 3. return corresponding lookup from DB'''
            if lookup and conds_fulfilled:
                lookup = lookup.find(self.tns + "dbLookupRequest")
                lookup_req = lookup.text
                self.db.execute(lookup_req)
                data = self.db.fetchall()
                if len(data) > 1:
                    # print("\tERROR: Problem on lookup, more then one element found returning FIRST.")
                    found = data[0]
                    return found[-1]
                found = data[0]
            
                return found[-1]
        
        return None
        
    
    def lookup_from_spec(self, class_name, var_name, variant):
        
        ''' 1. Get dbSpec Nodes'''
        time_map_node = self._get_timing_mapping(class_name, var_name)
        lst_db_spec = self._get_db_lookup_spec(time_map_node, variant)
        if not lst_db_spec: return None        
        
        for db_spec in lst_db_spec:

            ''' 2. check if all conditions specified in timingMapping.xml are fulfilled '''
            lookup = self._lookup_by_id(db_spec.attrib["lookupid"]) 
            conditions = self._get_conds_from_spec(db_spec)        
              
            ''' 3. return corresponding lookup from DB'''
            if lookup:
                lookup = lookup.find(self.tns + "dbLookupRequest")
                lookup_req = lookup.text
                return [lookup_req, db_spec]                        
        return None
    
    
    def conditions_from_spec(self, class_name, var_name, variant):
        
        ''' 1. Get dbSpec Nodes'''
        time_map_node = self._get_timing_mapping(class_name, var_name)
        lst_db_spec = self._get_db_lookup_spec(time_map_node, variant)
        if not lst_db_spec: return None        
        
        for db_spec in lst_db_spec:

            ''' 2. check if all conditions specified in timingMapping.xml are fulfilled '''
            lookup = self._lookup_by_id(db_spec.attrib["lookupid"]) 
            conditions = self._get_conds_from_spec(db_spec)        
              
            ''' 3. return corresponding lookup from DB'''
            if lookup:
                lookup = lookup.find(self.tns + "dbLookupRequest")

                return [conditions, db_spec]    
        
        return None
    
    
    def _check_conditions(self, conditions, proj_vars):
        
        for cond in conditions:
            if not self._proj_cond_fulfilled(cond, proj_vars):
                return False
        return True
             
    
    def _extended_line(self, val_x, x, y):
        d_x = x[-1] - x[1]
        d_y = y[-1] - y[1]
        m = d_y / d_x
        t = y[1] - x[1] * m
        result = m * val_x + t      
        if result < 0:
            return 0
        return result
            
     
    def _get_conds_from_spec(self, db_spec):
        try:
            varss = db_spec.findall(self.tns + "variable")
            conds = []
            
            if not varss:
                return []
            
            for var in varss:
                try:
                    val = var.find(self.tns + "value")
                    el = {}
                    el['name'] = var.attrib['name']
                    el['config'] = eval("IniConfig." + var.attrib['config']) 
                    
                    if(var.attrib['type'] == 'number'):
                        el['value'] = val.text
                    else:
                        el['value'] = eval(var.attrib['type'] + "." + val.text)
                except:
                    pass
                conds.append(el)
            return conds
        
        except:
            return []
        return conds
    
    
    def _get_timing_mapping(self, class_name, var_name):
        try:
            tmss = self.root.find(self.tns + "timingMappings")
            tms = tmss.findall(self.tns + "timingMapping")
            for tm in tms:
                if(tm.attrib['name'] == var_name and tm.attrib['class'] == class_name):
                    return tm
        except:
            return None
        return None
    
    
    def _get_db_lookup_spec(self, time_map_node, var_name):
        
        dbss = time_map_node.find(self.tns + "dbLookupSpecs")
        if dbss == None: return False
        found = dbss.findall(self.tns + "dbLookupSpec")
        if found == None: return False
        result = []
        
        for db in found:   
            try:            
                if db.attrib["id"] == var_name:
                    result.append(db)               
            except:
                pass
        return result
  
    
    def _lookup_by_id(self, lu_id):
        try:
            dblss = self.root.find(self.tns + "dbLookups")
            dbls = dblss.findall(self.tns + "dbLookup")
            for dbl in dbls:
                if dbl.attrib["id"] == lu_id:
                    return dbl            
        except:
            return False
        return False
    
    
    def _proj_cond_fulfilled(self, cond, proj_vars):
        # Check project property
        if cond['config'] == IniConfig.PROJECT:
            try:
                chk = proj_vars[cond["name"]] == cond["value"]
            except:
                return False
        return chk















