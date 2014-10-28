'''
Created on 28/10/2014

@author: Aitor Gomez Goiri

Implementation which uses "hmac" library [1].


[1] https://docs.python.org/2/library/hmac.html
'''

from hmac import HMAC
from kdf.nist import AbstractNIST

class NIST(AbstractNIST):
    
    def _get_reseted_hmac(self):
        return HMAC(self.secret, digestmod=self.digestmod)