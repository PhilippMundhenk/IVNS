log_dict = {}

'''===============================================================================
    1. components

     StdSecurityModuleAppLayer
==============================================================================='''

log_dict[1] = ["\tInterrupted current transmission", True]
log_dict[2] = ["\tThe received certificate was invalid", True]
log_dict[3] = ["\tReceived UNEXPECTED Message", True]
log_dict[4] = ["\tBusCoupler discarded message. ", True]

'''===============================================================================
    SecLwAuthSecurityModule, StdSecurLwSecModTimingFunctions
==============================================================================='''
log_dict[100] = ['No valid certificate defined for %s ', False]


'''===============================================================================
    API Core
==============================================================================='''

log_dict[200] = ["ERROR: Could not set %s and %s", True]
log_dict[201] = ["Class with id %s could not be created", True]
log_dict[202] = ["Unable to set setting: %s", True]

'''===============================================================================
    AbstractECU
==============================================================================='''
log_dict[300] = ["This ECU does not support HW Filtering! No filter installed.", True]


'''===============================================================================
    Base Components
==============================================================================='''
# CANFDMessage
log_dict[400] = ["WRONG BUS MESSAGE TYPE SPECIFIED. USE SEGMENTABLE MESSAGES!\n\n", True]
log_dict[401] = ["\n\nERROR function: --->        '%s'        <---", True]