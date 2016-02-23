'''
This module makes it possible to calculate timings depending
on input data
'''
import importlib

def call(func_or_var, *args):
    
    # static method call
    if isinstance(func_or_var, list):
        try:
            lst = func_or_var[0].split('.')
            le = func_or_var[0][:-len(lst[-1]) - 1]            
            impo = importlib.import_module(le)                    
            obj = impo.__dict__[lst[-1]]()  # @UnusedVariable            
            func_name = func_or_var[1]
            val = None
            val = eval("obj." + func_name + "(*args)")
            return val
        except:
            pass
#             ECULogger().log_traceback()
    
    if hasattr(func_or_var, '__call__'):
        return func_or_var(*args)
    else: 
        return func_or_var
    
    

#===============================================================================
#     StdCANBus
#===============================================================================

def calc_prop_delay(ecu_distance):
    t_propagation = 1.25 * (ecu_distance / (1 * 100000000))  # assume bit stuffing to extend frame
    return t_propagation


def calc_sending_time(msg_length_in_bit, effective_datarate):
    t_sending = 1.25 * (msg_length_in_bit / effective_datarate)  # Time to send and to receive (conciously 1 not 2)
    return t_sending

#===============================================================================
#     StdDatalinkLayer
#===============================================================================

def calc_collis_backoff(bittime):
    ''' wait for 3 bittimes then continue'''
    return bittime * 3 

#===============================================================================
#     SegmentTransportLayer
#===============================================================================

def segtl_send_time(msg_length, len_datafield):
    ''' a message of length msg_length is to be sent. The 
        maximum number of bytes that can be transmitted in 
        one frame is len_datafield'''
    return 0


def segtl_receive_time(msg_length, len_datafield):
    ''' a message of length msg_length was received and this
        is the time it takes to process this message 
        (i.e. to stick all segments together)
        one received segment was len_datafield long '''
    return 0

#===============================================================================
#     FakeSegmentTransportLayer
#===============================================================================

def fake_segtl_send_time(msg_length, len_datafield):
    ''' a message of length msg_length is to be sent. The 
        maximum number of bytes that can be transmitted in 
        one frame is len_datafield'''
    return 0


def fake_segtl_receive_time(msg_length, len_datafield):
    ''' a message of length msg_length was received and this
        is the time it takes to process this message 
        (i.e. to stick all segments together)
        one received segment was len_datafield long '''
    return 0

