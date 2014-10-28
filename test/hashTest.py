'''
Created on 14/07/2014

@author: Aitor Gomez Goiri
'''

import unittest
import binascii
from kdf.nist_crypto import NIST
from Crypto.Hash.SHA import SHA1Hash

class NISTTest(unittest.TestCase):
    """
    Test suite to check that I am using both HMAC_SHA1 using Crypto or XXX equivalently.
    """
    def setUp(self):
        # from http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
        self.result = {}
        # k = "", data = ""
        self.result['empty'] = b"fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
        # k ="key", data = "The quick brown fox jumps over the lazy dog"
        self.result['not_empty'] = b"de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
    
    def test_hmac_package(self):
        from hmac import HMAC
        import hashlib
        
        k_hex = binascii.hexlify("")
        hmac = HMAC(k_hex, digestmod=hashlib.sha1)
        self.assertEquals(hmac.hexdigest(), self.result['empty'])
        
                
        k_hex = binascii.hexlify("key")
        d_hex = binascii.hexlify("The quick brown fox jumps over the lazy dog")
                
        hmac1 = HMAC(k_hex, digestmod=hashlib.sha1)
        hmac1.update(d_hex)
        self.assertEquals(hmac.hexdigest(), self.result['empty'])
    
    def test_crypto_package_str(self):
        from Crypto.Hash import HMAC
        
        hmac = HMAC.new("", digestmod=SHA1Hash())
        self.assertEquals(hmac.hexdigest(), self.result['empty'])
        
        #hex_string = binascii.hexlify(self.not_empty)
        hmac = HMAC.new("key", digestmod=SHA1Hash())
        hmac.update("The quick brown fox jumps over the lazy dog")
        self.assertEquals(hmac.hexdigest(), self.result['not_empty'])
    
    def ttest_crypto_package_hex(self):
        from Crypto.Hash import HMAC
        
        k_hex = binascii.hexlify("")
        hmac = HMAC.new(k_hex, digestmod=SHA1Hash())
        self.assertEquals(hmac.hexdigest(), self.result['empty'])
        
        k_hex = binascii.hexlify("key")
        d_hex = binascii.hexlify("The quick brown fox jumps over the lazy dog")
        hmac = HMAC.new(k_hex, msg=d_hex, digestmod=SHA1Hash())
        # hmac.update(d_hex) # or without "msg" param and with this call
        self.assertEquals(hmac.hexdigest(), self.result['not_empty'])

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()