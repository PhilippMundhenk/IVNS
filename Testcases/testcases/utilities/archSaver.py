'''
Created on 13 Jul, 2015

@author: artur.mrowca
'''
from tools.singleton import Singleton
import random
import sys
import time
import os

class SaveRandom(Singleton):
    '''
    Uses a random seed for generation of random variables. If none given generates a new seed. Above that
    the seed used in this simulation is saved to a file
    '''
        
    def __init__(self, seed=False):        
        ''' Constructor
            
            Input:    seed    integer    seed used for this simulation
            Output:    -
        '''
        # create random generator
        self.seed = random.randint(0, sys.maxsize)        
        if seed: self.seed = seed
        self.ran = random.Random(self.seed)
        
        # save seed used to file
        self._save_seed_to_file()
        
        print("Using random Seed: %s" % self.seed)
        
    def _save_seed_to_file(self):
        ''' saves the seed used for this generator
            to a file
            
            Input:     -
            Output:    -
        '''
        
        cur_time = time.strftime("%I:%M:%S")
        cur_date = time.strftime("%d/%m/%Y")        
        save_path = "../../logs/" + "random_seeds.txt"        
        log_path = os.path.join(os.path.dirname(__file__), save_path)                
        with open(log_path, "a") as text_file:
            text_file.write("\n\nDate: %s\nTime: %s\nUsed Seed: %s" % (cur_date, cur_time, self.seed))
