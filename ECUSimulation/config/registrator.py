from tools.singleton import Singleton

class Registrator(Singleton):
    '''
    this class saves the mapping of the individual variables used in the can_registration.py, project_registration.py
    and the timing_registration.py
    '''
    def __init__(self):
        ''' Constructor
            
            Input:    -
            Output:   -
        '''
        # timing 
        self.reg_simple_timings = {}  # key class name value: dict:   key: Variable name // value: dict of registered entries:
                                        #                               dict: key: variant_name     value: time
                                        #                               i.e. call: time_or_func = self.reg_simple_timings[var_name][variant_name] 
        # project
        self.proj_cfgs = {}
        
        # CAN IDs  
        self.can_cfgs = {}
        
    
    def reg_simp_timing(self, section_name, variable_name, variant, time_or_func=None):
        ''' this method registers the value to be used for the timing variable in 
            the defined class. So e.g. ('TESLA', 'TESLA_KEY_EXCHANGE_KEY_LEN', 'bit_192', 0.5)
            would mean that the variable in timing.ini that is under the section TESLA and has
            the variable name TESLA_KEY_EXCHANGE_KEY_LEN can be set to the value bit_192. So if
            bit_192 is set for TESLA_KEY_EXCHANGE_KEY_LEN in the ini file then the value 0.5 will 
            be used in this program for this variable.
            If time_or_func is set to a function the function will be called with the parameters 
            defined in the code
            
            Input:  section_name    string      name of the section in the INI file
                    variable_name   string      name of the variable written as string
                    variant         string      key for the mapping to the value
                    time_or_fun     object      value that will be set in the program when variant 
                                                was set in the INI file
            Output: -
        '''
        self._append_to_dict([self.reg_simple_timings], section_name, variable_name, variant, time_or_func)
           
     
    def reg_proj_config(self, in_class_name, var_name, variant, time_or_func):
        ''' this method registers the value to be used for the project variable in 
            the defined class. So e.g. ('TESLA', 'TESLA_KEY_EXCHANGE_KEY_LEN', 'bit_192', 0.5)
            would mean that the variable in timing.ini that is under the section TESLA and has
            the variable name TESLA_KEY_EXCHANGE_KEY_LEN can be set to the value bit_192. So if
            bit_192 is set for TESLA_KEY_EXCHANGE_KEY_LEN in the ini file then the value 0.5 will 
            be used in this program for this variable.
            If time_or_func is set to a function the function will be called with the parameters 
            defined in the code
            
            Input:  section_name    string      name of the section in the INI file
                    variable_name   string      name of the variable written as string
                    variant         string      key for the mapping to the value
                    time_or_fun     object      value that will be set in the program when variant 
                                                was set in the INI file
            Output: -
        '''
        self._append_to_dict([self.proj_cfgs], in_class_name, var_name, variant, time_or_func)
        
    
    def reg_can_ids(self, in_class_name, var_name, variant, time_or_func):
        ''' this method registers the value to be used for the can id variable in 
            the defined class. So e.g. ('TESLA', 'TESLA_KEY_EXCHANGE_KEY_LEN', 'bit_192', 0.5)
            would mean that the variable in timing.ini that is under the section TESLA and has
            the variable name TESLA_KEY_EXCHANGE_KEY_LEN can be set to the value bit_192. So if
            bit_192 is set for TESLA_KEY_EXCHANGE_KEY_LEN in the ini file then the value 0.5 will 
            be used in this program for this variable.
            If time_or_func is set to a function the function will be called with the parameters 
            defined in the code
            
            Input:  section_name    string      name of the section in the INI file
                    variable_name   string      name of the variable written as string
                    variant         string      key for the mapping to the value
                    time_or_fun     object      value that will be set in the program when variant 
                                                was set in the INI file
            Output: -
        '''
        self._append_to_dict([self.can_cfgs], in_class_name, var_name, variant, time_or_func)
           
     
    def _append_to_dict(self, lst_dict, lay_1, lay_2, lay_3, val=None):
        ''' sets a value to a dictionaries on the third layer. This value can
            be accessed using lst_dict[lay_1][lay_2][lay_3]
            
            Input:  lst_dict     dictionary        dict that will be extended
                    lay_1        object            key of first layer
                    lay_2        object            key of second layer
                    lay_3        object            key of third layer
            Output: -
        '''
        try:
            lst_dict[0][lay_1]
        except:
            lst_dict[0][lay_1] = {}            
        try:
            lst_dict[0][lay_1][lay_2]
        except:
            lst_dict[0][lay_1][lay_2] = {}         
        try:
            lst_dict[0][lay_1][lay_2][lay_3]
        except:
            lst_dict[0][lay_1][lay_2][lay_3] = {}
        
        if val != None:
            lst_dict[0][lay_1][lay_2][lay_3] = val
    
    
    def _remove(self, element, a_list):
        ''' tries to remove the given element from the
            given list
            
            Input:  element    object      element of the list
                    a_list     list        list where the element will be removed
            Output: -
        '''
        try:
            a_list.remove(element)
        except:
            pass
    
    
