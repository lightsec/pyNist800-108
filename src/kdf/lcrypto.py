'''
Created on 28/10/2014

@author: Aitor Gomez Goiri
'''

import Crypto.Hash.HMAC as cHMAC
from kdf.nist import AbstractNIST

class NIST(AbstractNIST):
    
    def _get_reseted_hmac(self):
        return cHMAC.new(self.secret, digestmod=self.digestmod)