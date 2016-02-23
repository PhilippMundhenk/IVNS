class Message():
    
    def __init__(self, ID, interval):
        self.ID = ID
        self.interval = interval
    
    def get_ID(self):
        return self.ID
        
    def get_interval(self):
        return self.interval