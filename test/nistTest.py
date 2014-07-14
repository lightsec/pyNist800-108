'''
Created on 14/07/2014

@author: Aitor Gomez Goiri
'''

import unittest
import hashlib
import nist

class NISTTest(unittest.TestCase):
    
    def _test_NIST_UseCase(self, testCase):
        self.nist.set_hmac( testCase["digestmod"], testCase["ki"] );
        #ret = self.nist.derive_key( len(testCase["ko"])*8, testCase["fixedInput"] )
        ret = self.nist.derive_key( testCase["l"], testCase["fixedInput"] )
        print ret
        self.assertSequenceEqual(ret, testCase["ko"])
    
    def test_NIST(self):
        self._test_NIST_UseCase( self.case1 )

    def setUp(self):
        self.nist = nist.NIST()
        
        # [PRF=HMAC_SHA1]
        # [CTRLOCATION=BEFORE_FIXED]
        # [RLEN=8_BITS]
        # INPUT:
        # L = 128
        # KI = 8723b723aa398f94af2b61c06cd99de01ef6497b
        # FixedInputDataByteLen = 60
        # FixedInputData = 8aece231d69ab033c9efe824c398da94777b260887c609a34c0206e4abcce0f5709356a7dbb92b8b0d387ccb4945d3b8a5490972205e72531f961b3d
        #         Binary rep of i = 01
        #         instring = 018aece231d69ab033c9efe824c398da94777b260887c609a34c0206e4abcce0f5709356a7dbb92b8b0d387ccb4945d3b8a5490972205e72531f961b3d
        # OUTPUT:
        # KO = 7596a2c6e19c8f5f52e1e7c6380fa5e5
        self.case1 = {"l": 128, "digestmod": hashlib.sha1, "ki": None, "fixedInput": None, "ko": None}
        # http://stackoverflow.com/questions/7380460/byte-array-in-python
        self.case1["ki"] = bytearray( b'\x87\x23\xb7\x23\xaa\x39\x8f\x94\xaf\x2b\x61\xc0\x6c\xd9\x9d\xe0\x1e\xf6\x49\x7b' )
        #self.case1["ki"] = bytearray( b'8723b723aa398f94af2b61c06cd99de01ef6497b' )
        self.case1["fixedInput"] = bytearray(b'\x8a\xec\xe2\x31\xd6\x9a\xb0\x33\xc9\xef\xe8\x24\xc3\x98\xda\x94' +
                                             b'\x77\x7b\x26\x08\x87\xc6\x09\xa3\x4c\x02\x06\xe4\xab\xcc\xe0\xf5\x70' +
                                             b'\x93\x56\xa7\xdb\xb9\x2b\x8b\x0d\x38\x7c\xcb\x49\x45\xd3\xb8\xa5\x49' +
                                             b'\x09\x72\x20\x5e\x72\x53\x1f\x96\x1b\x3d')
        self.case1["ko"] = bytearray( b'/x75/x96/xa2/xc6/xe1/x9c/x8f/x5f/x52/xe1/xe7/xc6/x38/x0f/xa5/xe5' )
        #self.case1["ko"] = bytearray( b'7596a2c6e19c8f5f52e1e7c6380fa5e5' )


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()