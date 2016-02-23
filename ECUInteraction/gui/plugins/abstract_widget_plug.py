'''
Created on 27 Apr, 2015

@author: artur.mrowca
'''
from PyQt4.Qt import QObject

class AbstractWidgetPlugin(object):
    '''
    This class is the base class for all Widgets that are inserted into
    the GUI via a Plug In
    '''

#     def __init__(self, *args):
#         QObject.__init__(*args)        

        
    def get_combobox_name(self):
        raise NotImplementedError("get_combobox_name() method was not implemented by %s " % (self.__class__))
    
    def get_widget(self, parent):
        raise NotImplementedError("get_widget() method was not implemented by %s " % (self.__class__))
