'''
Created on 14/07/2014

@author: Aitor Gomez Goiri
'''

import unittest
import hashlib
import nist

class NISTTest(unittest.TestCase):
    
    def setUp(self):
        self.nist = nist.NIST()
        
    def _test_NIST_UseCase(self, testCase):
        self.nist.set_hmac( testCase["digestmod"], testCase["ki"] );
        #ret = self.nist.derive_key( len(testCase["ko"])*8, testCase["fixedInput"] )
        ret = self.nist.derive_key( testCase["l"], testCase["fixedInput"] )
        self.assertSequenceEqual(ret, testCase["ko"])
    
    def test_NIST1(self):
        """
        [PRF=HMAC_SHA1]
        [CTRLOCATION=BEFORE_FIXED]
        [RLEN=8_BITS]
        INPUT:
        L = 128
        KI = 8723b723aa398f94af2b61c06cd99de01ef6497b
        FixedInputDataByteLen = 60
        FixedInputData = 8aece231d69ab033c9efe824c398da94777b260887c609a34c0206e4abcce0f5709356a7dbb92b8b0d387ccb4945d3b8a5490972205e72531f961b3d
                Binary rep of i = 01
                instring = 018aece231d69ab033c9efe824c398da94777b260887c609a34c0206e4abcce0f5709356a7dbb92b8b0d387ccb4945d3b8a5490972205e72531f961b3d
        OUTPUT:
        KO = 7596a2c6e19c8f5f52e1e7c6380fa5e5
        """
        case = {"l": 128, "digestmod": hashlib.sha1, "ki": None, "fixedInput": None, "ko": None}
        case["ki"] = bytearray( b'\x87\x23\xb7\x23\xaa\x39\x8f\x94\xaf\x2b\x61\xc0\x6c\xd9\x9d\xe0\x1e\xf6\x49\x7b' )
        case["fixedInput"] = bytearray(b'\x8a\xec\xe2\x31\xd6\x9a\xb0\x33\xc9\xef\xe8\x24\xc3\x98\xda\x94' +
                                       b'\x77\x7b\x26\x08\x87\xc6\x09\xa3\x4c\x02\x06\xe4\xab\xcc\xe0\xf5\x70' +
                                       b'\x93\x56\xa7\xdb\xb9\x2b\x8b\x0d\x38\x7c\xcb\x49\x45\xd3\xb8\xa5\x49' +
                                       b'\x09\x72\x20\x5e\x72\x53\x1f\x96\x1b\x3d')
        case["ko"] = bytearray( b'\x75\x96\xa2\xc6\xe1\x9c\x8f\x5f\x52\xe1\xe7\xc6\x38\x0f\xa5\xe5' )
        self._test_NIST_UseCase( case )
    
    def test_NIST2(self):
        """
        [PRF=HMAC_SHA1]
        [CTRLOCATION=BEFORE_FIXED]
        [RLEN=8_BITS]
        INPUT:
        L = 128
        KI = 216fe07662d332244962dd26b3dc9d4ec77783b4
        FixedInputDataByteLen = 60
        FixedInputData = 365047101061fd650db1c8356da8a3cc1494c0ec7f9eda7264150391ed07bcb15d86fba7399861061dd37cddbbdad38d1d4902d39ce1f0cd627965fe
                Binary rep of i = 01
                instring = 01365047101061fd650db1c8356da8a3cc1494c0ec7f9eda7264150391ed07bcb15d86fba7399861061dd37cddbbdad38d1d4902d39ce1f0cd627965fe
        OUTPUT:
        KO = 05e1a344b073117cb8743647e5320449
        """
        case = {"l": 128, "digestmod": hashlib.sha1, "ki": None, "fixedInput": None, "ko": None}
        case["ki"] = bytearray( b'\x21\x6f\xe0\x76\x62\xd3\x32\x24\x49\x62\xdd\x26\xb3\xdc\x9d\x4e\xc7\x77\x83\xb4' )
        case["fixedInput2"] = bytearray( b'\x36\x50\x47\x10\x10\x61\xfd\x65\x0d\xb1\xc8\x35\x6d\xa8\xa3\xcc\x14\x94' +
                                        b'\xc0\xec\x7f\x9e\xda\x72\x64\x15\x03\x91\xed\x07\xbc\xb1\x5d\x86\xfb\xa7' +
                                        b'\x39\x98\x61\x06\x1d\xd3\x7c\xdd\xbb\xda\xd3\x8d\x1d\x49\x02\xd3\x9c\xe1' +
                                        b'\xf0\xcd\x62\x79\x65\xfe')
        case["fixedInput"] = bytearray( b'\x36\x50\x47\x10\x10\x61\xfd\x65\x0d\xb1\xc8\x35\x6d\xa8\xa3\xcc\x14\x94\xc0\xec\x7f\x9e\xda\x72\x64\x15\x03\x91\xed\x07\xbc\xb1\x5d\x86\xfb\xa7\x39\x98\x61\x06\x1d\xd3\x7c\xdd\xbb\xda\xd3\x8d\x1d\x49\x02\xd3\x9c\xe1\xf0\xcd\x62\x79\x65\xfe' )
        case["ko"] = bytearray( b'\x05\xe1\xa3\x44\xb0\x73\x11\x7c\xb8\x74\x36\x47\xe5\x32\x04\x49' )
        self._test_NIST_UseCase( case )
        
    def test_NIST3(self):
        """
        [PRF=HMAC_SHA1]
        [CTRLOCATION=BEFORE_FIXED]
        [RLEN=8_BITS]
        L = 512
        KI = eda0134ca5238efece65a5ee02bc356f4fe0d5d4
        FixedInputDataByteLen = 60
        FixedInputData = c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
               Binary rep of i = 01
               instring = 01c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
               Binary rep of i = 02
               instring = 02c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
               Binary rep of i = 03
               instring = 03c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
               Binary rep of i = 04
               instring = 04c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
        KO = 5d791c5b6a337cfb4d3b9cf73dd2afc5ff3fe1737880e54bff2f457750398b55fb4ae1c39a4c86dd72ffd453bbf4dccbeaf9a09b2e5ffe4d41f56a67898484a0
        """
        case = {"l": 512, "digestmod": hashlib.sha1, "ki": None, "fixedInput": None, "ko": None}
        case["ki"] = bytearray( b'\xed\xa0\x13\x4c\xa5\x23\x8e\xfe\xce\x65\xa5\xee\x02\xbc\x35\x6f\x4f\xe0\xd5\xd4' )
        case["fixedInput"] = bytearray( b'\xc8\xc4\xf8\x53\x82\xb3\xe3\xd4\xac\xc8\x84\xfd\xff\x98\x58\x2d\x0c\x8c\x61\xf6\x9d\x38\x1b\x0c\x08\x03\xbe\xf2\x9b\xd4\xe1\x42\x78\x45\x22\x38\x6a\x86\xee\x0f\x86\x4b\xff\xc5\xff\x13\xeb\x7c\xb0\x6a\x6e\x32\x4e\x98\xeb\x6d\x56\x1e\xcb\xb3' )
        case["ko"] = bytearray( b'\x5d\x79\x1c\x5b\x6a\x33\x7c\xfb\x4d\x3b\x9c\xf7\x3d\xd2\xaf\xc5\xff\x3f\xe1\x73\x78\x80\xe5\x4b\xff\x2f\x45\x77\x50\x39\x8b\x55\xfb\x4a\xe1\xc3\x9a\x4c\x86\xdd\x72\xff\xd4\x53\xbb\xf4\xdc\xcb\xea\xf9\xa0\x9b\x2e\x5f\xfe\x4d\x41\xf5\x6a\x67\x89\x84\x84\xa0' )
        self._test_NIST_UseCase( case )

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()