'''
Created on 28/10/2014

@author: Aitor Gomez Goiri
'''

import Crypto.Hash.HMAC as cHMAC
from kdf.nist import AbstractNIST

class NIST(AbstractNIST):
    
    def _get_reseted_hmac(self):
        # http://crypto.stackexchange.com/questions/8272/injecting-salt-into-pycrypto-kdf-useful
        return cHMAC.new(self.secret, msg=self.salt, digestmod=self.digestmod)