from configparser import ConfigParser
from tools.singleton import Singleton
from enums.gen_cfg_enums import IniConfig
from config.timing_db_admin import TimingDBMap
import logging

class ConfigIO(Singleton):
    '''
    Input / Output Processor for the configuration of the project's, timing's and can's initial
    state
    '''

    
    def load_cfg(self, reg_object, file_path, variant, proj_vals=None): 
        ''' loads a config file and sets the corresponding
            parameters 
        
            Input:  reg_object    Registrator    object corresponding to the mapping of configurations loaded
                    file_path     string         path to the .ini file containing the configuration
                    variant       IniConfig      type of config file that is to be loaded
                    proj_vals     list           optional: list of project values 
            Output: -
        '''
        
        # load timing.ini
        if variant == IniConfig.TIMING:
            return self._load_timing_cfg(reg_object, file_path, proj_vals)

        # load project.ini
        if variant == IniConfig.PROJECT:
            return self._load_project_cfg(reg_object, file_path)        
        
    
    def generate_raw_cfg(self, registrator, file_path, variant):
        ''' generates a raw config ini file from a 
            Registration object dependant of the variant passed
            
            Input:  registrator    Registrator    object corresponding to the mapping of configurations loaded
                    file_path      string         path to the .ini file containing the configuration
                    variant       IniConfig       type of config file that is to be generated
        '''
        
        # timing.ini
        if variant == IniConfig.TIMING:
            self._generate_timing_cfg(registrator, file_path)
        
        # project.ini    
        if variant == IniConfig.PROJECT:
            self._generate_project_cfg(registrator, file_path)
            
        # can_configuration.ini
        if variant == IniConfig.CAN_CFG:
            self._generate_can_cfg(registrator, file_path)

    
    def _add_sections(self, config, lst_sec_names):
        ''' used to add a section to the ini file
            during ini file generation
            
            Input:  config            ConfigParser    ConfigParser object holding the information
                    lst_sec_names     list            list of section names to be added
            Output: -
        ''' 
        for el in lst_sec_names:
            try:
                config.add_section(el)
            except:
                pass

    
    def _add_simp_variants(self, config, el_dict):
        ''' writes simple variants to file 
            
            Input:  config          ConfigParser    ConfigParser object holding the information
                    el_dict         dictionary      contains the information about elements to add
            Output: -
        '''
        for el in el_dict:
            for el2 in el_dict[el]:
                for el3 in el_dict[el][el2]:
                    try: config.set(el, el2, el3)
                    except: logging.info("\t Could not ADD Element")


    def _cfg_sec_map(self, cfg, section):
        ''' Maps the data read out of the ini file to a dictionary 
            
            Input:  config          ConfigParser    ConfigParser object holding the information
                    section         string          name of the section that is currently read out  
            Output: el_dict         dictionary      contains the information about elements mapped
        '''
        # initialize
        dict1 = {}
        options = cfg.options(section)
        
        # get options and write dict
        for option in options:
            try:
                dict1[option] = cfg.get(section, option)
            except:
                logging.info("\texception on %s!" % option)
                dict1[option] = None
        return dict1

    
    def _generate_timing_cfg(self, registrator, file_path):
        ''' creates a raw timing ini config file 
        
        Input:  registrator    Registrator    object corresponding to the mapping of configurations loaded
                file_path      string         path to the .ini file containing the configuration
        Output: -
        '''
        
        # extract types dicts 
        cfg = ConfigParser()
        simp_t = registrator.reg_simple_timings
        db_vals = registrator.db_lookup_timings
                
        # create config 
        cfgfile = open(file_path, 'w')
        self._add_sections(cfg, simp_t.keys())
        self._add_sections(cfg, db_vals.keys())
        
        # add variants 
        self._add_simp_variants(cfg, simp_t)
        self._add_simp_variants(cfg, db_vals)
        
        # write file
        cfg.write(cfgfile)
        cfgfile.close()
        
    
    def _generate_can_cfg(self, registrator, file_path):
        ''' creates a raw ini config file for the can ini file
        
            Input:  registrator    Registrator    object corresponding to the mapping of configurations loaded
                    file_path      string         path to the .ini file containing the configuration
            Output: -
        '''
        
        # extract types dicts 
        cfg = ConfigParser()
        simp_t = registrator.can_cfgs
                
        # create config 
        cfgfile = open(file_path, 'w')
        self._add_sections(cfg, simp_t.keys())
        
        # add variants 
        self._add_simp_variants(cfg, simp_t)
        
        # Write File 
        cfg.write(cfgfile)
        cfgfile.close()
        
    
    def _generate_project_cfg(self, reg_object, file_path):
        ''' creates a raw ini config file for the project ini file
        
            Input:  registrator    Registrator    object corresponding to the mapping of configurations loaded
                    file_path      string         path to the .ini file containing the configuration
            Output: -
        '''
        
        # extract types dicts
        cfg = ConfigParser()
        simp_t = reg_object.proj_cfgs
                
        # create config
        cfgfile = open(file_path, 'w')
        self._add_sections(cfg, simp_t.keys())
        
        # add variants 
        self._add_simp_variants(cfg, simp_t)
        
        # write file
        cfg.write(cfgfile)
        cfgfile.close()


    def _load_dblookup_vals(self, cfg, db_lookups, proj_vals):
        ''' loads defined values from the database lookup if
            defined (deprecated)
            
            Input:     -
            Output:    -
        '''
        out_lst = []
        for sec in db_lookups:
            for variable in db_lookups[sec]:                
                try:
                    symb = self._cfg_sec_map(cfg, sec)[variable.lower()]
                    db = TimingDBMap()
                    vala = db.lookup_time(sec, variable, symb, proj_vals)
                    if vala != None:
                        out_lst.append([variable, vala])                                        
                except:
                    pass
        return out_lst
    
    
    def _load_project_cfg(self, reg_object, file_path):
        ''' loads the timings and returns them, so       
            returns a list of information for commands
                e.g. [FSEGTL_SEND_PROCESS, 3]
                    i.e. FSEGTL_SEND_PROCESS = 3 
                    
            Input:  registrator    Registrator    object corresponding to the mapping of configurations loaded
                    file_path      string         path to the .ini file containing the configuration
            Output: -
        
        '''
        # create parser
        cfg = ConfigParser()
        cfg.read(file_path)
    
        # load timings
        lst = self._load_simple_timing(cfg, reg_object.proj_cfgs)
    
        return lst        

    
    def _load_simple_timing(self, cfg, reg_simple_timings):
        ''' loads all simply registered timings 
            returns a list of information for commands 
        
            Input:  cfg                    ConfigParser    configparser object coresponding to the ini file data
                    reg_simple_timings     dictionary      contains the timing values depending on the section and variable name
            Output: out_lst                list            list of information for commands 
        '''
        out_lst = []
        for sec in reg_simple_timings:
            for variable in reg_simple_timings[sec]:                
                try:
                    symb = self._cfg_sec_map(cfg, sec)[variable.lower()]
                    try: 
                        float(symb)
                        works = True
                    except:
                        works = False
                    
                    if works:
                        out_lst.append([variable, float(symb)])   
                        continue  
                    vala = reg_simple_timings[sec][variable][symb]                    
                    out_lst.append([variable, vala])                                        
                except:
                    pass
        return out_lst

    
    def _load_timing_cfg(self, reg_object, file_path, proj_vals):
        ''' loads the timings and returns them, so       
            returns a list of information for commands
                e.g. [FSEGTL_SEND_PROCESS, 3]
                    i.e. FSEGTL_SEND_PROCESS = 3 
        
            Input:  registrator    Registrator    object corresponding to the mapping of configurations loaded
                    file_path      string         path to the .ini file containing the configuration
                    proj_vals      list           - 
            Output: -
        '''
        # parser
        cfg = ConfigParser()
        cfg.read(file_path)
    
        # timings
        lst = self._load_simple_timing(cfg, reg_object.reg_simple_timings)
        
        return lst
    





    

                        
        
