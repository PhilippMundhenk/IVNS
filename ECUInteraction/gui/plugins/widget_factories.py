import os
import imp
from tools.singleton import Singleton
import sys
import traceback
import logging
from gui.plugins.views.event_line_view_impl import EventlineViewPlugin
from tools.ecu_logging import try_ex

class AbstractStandardFactory(Singleton):
    def __init__(self):
        '''
        Constructor
        '''
        self.create_dict = {}
        self.load_classes()
        
    def add_class(self, class_id, class_object):
        self.create_dict[class_id] = class_object
        
    @try_ex
    def make(self, class_id):
        try:
            ChoClass = self.create_dict[class_id]
            return ChoClass()
        except:
            logging.error(traceback.format_exc())
            logging.warning("Class with id %s could not be created" % class_id)
            return None
        
    def createable_objects(self):
        return self.create_dict.keys()
    
    def load_classes(self):
        raise NotImplementedError('Class %s did not implement the method load_classes' % self.__class__)
    
    def _add_classes(self, path, variable):                
        for file in os.listdir(path):
            if file[-2:] == 'py':
                try:
                    impo = imp.load_source('util', os.path.join(path, file))
                except:
                    continue
                
                ''' Load all classes '''
                for da_key in impo.__dict__.keys():
                    if da_key[:2] != '__' and da_key[:8] != 'Abstract':
                        
                        # check if specified variable exists
                        try:
                            try:
                                obj = impo.__dict__[da_key](ignore=True)
                            except:
                                obj = impo.__dict__[da_key]()
                        
                            if (eval("obj.%s" % variable)):    
                                self.add_class(da_key, impo.__dict__[da_key])
                        except:
                            continue
    
class ViewerPluginFactory(AbstractStandardFactory):
    '''
       Factory to create Viewer Plugins
    '''
    
    def __init__(self, *args, **kwargs):
        AbstractStandardFactory.__init__(self, *args, **kwargs)
               

    def load_classes(self):                
        self._add_classes(os.path.join(os.path.dirname(__file__), r'views'), '_VIEWER')
        
    

class SettingsPluginFactory(AbstractStandardFactory):
    '''
    Factory to create Settings Plugins
    '''

    def __init__(self, *args, **kwargs):
        AbstractStandardFactory.__init__(self, *args, **kwargs)
        
    def load_classes(self):        
        self._add_classes(os.path.join(os.path.dirname(__file__), r'settings'), '_SETTINGS')
