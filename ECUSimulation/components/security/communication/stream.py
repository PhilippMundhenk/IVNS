
class MessageStream(object):
    '''
    This class specifies a message stream
    '''
    def __init__(self, sender, receiver_list, msg_id=None, validity_time=999999999999999, earl_req=0, latest_req=float('inf'), periodic_interval=None, start_time=None, sending_interval=None, disclosure_delay=None):
        ''' Constructor
        
            Input:  sender                string    identifier of the ECU sending this stream
                    receiver_list         list      list of identifiers of ECUs receiving this stream
                    msg_id                integer   message identifier for this stream
                    validity_time         float     time until which this stream is valid
                    earl_req              float     earliest time at which this stream can be requested
                    latest_req            float     latest time at which this stream can be requested
                    periodic_interval     float     interval in which the message is sent (only for Tesla)
                    start_time            float     start_time at which the first message of this stream will be sent (only for Tesla)
                    sending_interval      float     sending interval in which this message will be sent (only for Tesla)
                    disclosure_delay      float     disclosure delay within which the key for a previous message will be disclosed (only for Tesla)
            Output: -
        '''
        self.sender_id = sender
        self.receivers = receiver_list        
        
        self.message_id = msg_id
        self.validity = validity_time
        self.valid_till = earl_req + validity_time
        
        self.earliest_req = earl_req
        self.latest_req = latest_req
        self.periodic_interval = periodic_interval
        
        # for TESLA
        self.start_time = start_time
        self.sending_interval = sending_interval
        self.disclosure_delay = disclosure_delay