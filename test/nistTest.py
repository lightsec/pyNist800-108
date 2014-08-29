'''
Created on 14/07/2014

@author: Aitor Gomez Goiri
'''

import unittest
import hashlib
from kdf.nist import NIST

class NISTTest(unittest.TestCase):
    
    def setUp(self):
        self.nist = NIST()
        
    def _test_NIST_UseCase(self, testCase):
        self.nist.set_hmac( testCase["digestmod"], testCase["ki"] )
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
        case["fixedInput"] = bytearray(b'\x8a\xec\xe2\x31\xd6\x9a\xb0\x33\xc9\xef' +
                                       b'\xe8\x24\xc3\x98\xda\x94\x77\x7b\x26\x08' +
                                       b'\x87\xc6\x09\xa3\x4c\x02\x06\xe4\xab\xcc' +
                                       b'\xe0\xf5\x70\x93\x56\xa7\xdb\xb9\x2b\x8b' +
                                       b'\x0d\x38\x7c\xcb\x49\x45\xd3\xb8\xa5\x49' +
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
        case["fixedInput"] = bytearray( b'\x36\x50\x47\x10\x10\x61\xfd\x65\x0d\xb1' +
                                        b'\xc8\x35\x6d\xa8\xa3\xcc\x14\x94\xc0\xec' +
                                        b'\x7f\x9e\xda\x72\x64\x15\x03\x91\xed\x07' +
                                        b'\xbc\xb1\x5d\x86\xfb\xa7\x39\x98\x61\x06' +
                                        b'\x1d\xd3\x7c\xdd\xbb\xda\xd3\x8d\x1d\x49' +
                                        b'\x02\xd3\x9c\xe1\xf0\xcd\x62\x79\x65\xfe')
        #case["fixedInput"] = bytearray( b'\x36\x50\x47\x10\x10\x61\xfd\x65\x0d\xb1\xc8\x35\x6d\xa8\xa3\xcc\x14\x94\xc0\xec\x7f\x9e\xda\x72\x64\x15\x03\x91\xed\x07\xbc\xb1\x5d\x86\xfb\xa7\x39\x98\x61\x06\x1d\xd3\x7c\xdd\xbb\xda\xd3\x8d\x1d\x49\x02\xd3\x9c\xe1\xf0\xcd\x62\x79\x65\xfe' )
        case["ko"] = bytearray( b'\x05\xe1\xa3\x44\xb0\x73\x11\x7c\xb8\x74\x36\x47\xe5\x32\x04\x49' )
        self._test_NIST_UseCase( case )
        
    def test_NIST3(self):
        """
        [PRF=HMAC_SHA1]
        [CTRLOCATION=BEFORE_FIXED]
        [RLEN=8_BITS]
        INPUT:
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
        OUTPUT:
            KO = 5d791c5b6a337cfb4d3b9cf73dd2afc5ff3fe1737880e54bff2f457750398b55fb4ae1c39a4c86dd72ffd453bbf4dccbeaf9a09b2e5ffe4d41f56a67898484a0
        """
        case = {"l": 512, "digestmod": hashlib.sha1, "ki": None, "fixedInput": None, "ko": None}
        case["ki"] = bytearray( b'\xed\xa0\x13\x4c\xa5\x23\x8e\xfe\xce\x65\xa5\xee\x02\xbc\x35\x6f\x4f\xe0\xd5\xd4' )
        case["fixedInput"] = bytearray( b'\xc8\xc4\xf8\x53\x82\xb3\xe3\xd4\xac\xc8' + 
                                        b'\x84\xfd\xff\x98\x58\x2d\x0c\x8c\x61\xf6' +
                                        b'\x9d\x38\x1b\x0c\x08\x03\xbe\xf2\x9b\xd4' +
                                        b'\xe1\x42\x78\x45\x22\x38\x6a\x86\xee\x0f' +
                                        b'\x86\x4b\xff\xc5\xff\x13\xeb\x7c\xb0\x6a' +
                                        b'\x6e\x32\x4e\x98\xeb\x6d\x56\x1e\xcb\xb3' )
        case["ko"] = bytearray( b'\x5d\x79\x1c\x5b\x6a\x33\x7c\xfb\x4d\x3b' +
                                b'\x9c\xf7\x3d\xd2\xaf\xc5\xff\x3f\xe1\x73' +
                                b'\x78\x80\xe5\x4b\xff\x2f\x45\x77\x50\x39' +
                                b'\x8b\x55\xfb\x4a\xe1\xc3\x9a\x4c\x86\xdd' +
                                b'\x72\xff\xd4\x53\xbb\xf4\xdc\xcb\xea\xf9' +
                                b'\xa0\x9b\x2e\x5f\xfe\x4d\x41\xf5\x6a\x67\x89\x84\x84\xa0' )
        self._test_NIST_UseCase( case )
        
    def test_NIST4(self):
        """
        [PRF=HMAC_SHA256]
        [CTRLOCATION=BEFORE_FIXED]
        [RLEN=8_BITS]
        INPUT:
            L = 128
            KI = 2ce3a4a13bbf845a38999ef3c2a68385355fbbb0d6997c0bea7c3fecdc7f6745
            FixedInputDataByteLen = 60
            FixedInputData = 8505879d9c93d0b66a29a4d334c257a7824538ebcf151c0b55de0b757dda28fd462c17cbdd8b529f9c183b786385499ff61fa1b736fb1579cf2f8e88
                   Binary rep of i = 01
                   instring = 018505879d9c93d0b66a29a4d334c257a7824538ebcf151c0b55de0b757dda28fd462c17cbdd8b529f9c183b786385499ff61fa1b736fb1579cf2f8e88
        OUTPUT:
            KO = ee9a34656d9d98384f49d35f088cd674
        """
        case = {"l": 128, "digestmod": hashlib.sha256, "ki": None, "fixedInput": None, "ko": None}
        case["ki"] = bytearray( b'\x2c\xe3\xa4\xa1\x3b\xbf\x84\x5a\x38\x99' +
                                b'\x9e\xf3\xc2\xa6\x83\x85\x35\x5f\xbb\xb0' +
                                b'\xd6\x99\x7c\x0b\xea\x7c\x3f\xec\xdc\x7f\x67\x45' )
        case["fixedInput"] = bytearray( b'\x85\x05\x87\x9d\x9c\x93\xd0\xb6\x6a\x29' +
                                        b'\xa4\xd3\x34\xc2\x57\xa7\x82\x45\x38\xeb' +
                                        b'\xcf\x15\x1c\x0b\x55\xde\x0b\x75\x7d\xda' +
                                        b'\x28\xfd\x46\x2c\x17\xcb\xdd\x8b\x52\x9f' +
                                        b'\x9c\x18\x3b\x78\x63\x85\x49\x9f\xf6\x1f' +
                                        b'\xa1\xb7\x36\xfb\x15\x79\xcf\x2f\x8e\x88' )
        case["ko"] = bytearray( b'\xee\x9a\x34\x65\x6d\x9d\x98\x38\x4f\x49\xd3\x5f\x08\x8c\xd6\x74' )
        self._test_NIST_UseCase( case )
    
    def test_NIST5(self):
        """
        [PRF=HMAC_SHA256]
        [CTRLOCATION=BEFORE_FIXED]
        [RLEN=8_BITS]
        INPUT:
            L = 512
            KI = a486b3eb053570b3b99efddcbc76685c0b53f398d581ffd8f9f372e85132d0f0
            FixedInputDataByteLen = 60
            FixedInputData = 3cc25799712eeb86a96f2c4abe68c4f0ba767411e8d9f9771a9e9c9085c84129ef8be7105e9542bad5798c4672a3d7cc30f35ecfcbc4b470e260e9a5
               Binary rep of i = 01
               instring = 013cc25799712eeb86a96f2c4abe68c4f0ba767411e8d9f9771a9e9c9085c84129ef8be7105e9542bad5798c4672a3d7cc30f35ecfcbc4b470e260e9a5
               Binary rep of i = 02
               instring = 023cc25799712eeb86a96f2c4abe68c4f0ba767411e8d9f9771a9e9c9085c84129ef8be7105e9542bad5798c4672a3d7cc30f35ecfcbc4b470e260e9a5
        OUTPUT:
            KO = 08751581291d5a4109cb10244b7a42363f0e175bce0fcd1207ec8a5ca829d80022521e8d0fa8231ce975039062e1744cc52cad7fbdc126740c905bbc0bc4a764
        """
        case = {"l": 512, "digestmod": hashlib.sha256, "ki": None, "fixedInput": None, "ko": None}
        case["ki"] = bytearray( b'\xa4\x86\xb3\xeb\x05\x35\x70\xb3\xb9\x9e' +
                                b'\xfd\xdc\xbc\x76\x68\x5c\x0b\x53\xf3\x98' +
                                b'\xd5\x81\xff\xd8\xf9\xf3\x72\xe8\x51\x32\xd0\xf0' )
        case["fixedInput"] = bytearray( b'\x3c\xc2\x57\x99\x71\x2e\xeb\x86\xa9\x6f' +
                                        b'\x2c\x4a\xbe\x68\xc4\xf0\xba\x76\x74\x11' +
                                        b'\xe8\xd9\xf9\x77\x1a\x9e\x9c\x90\x85\xc8' +
                                        b'\x41\x29\xef\x8b\xe7\x10\x5e\x95\x42\xba' +
                                        b'\xd5\x79\x8c\x46\x72\xa3\xd7\xcc\x30\xf3' +
                                        b'\x5e\xcf\xcb\xc4\xb4\x70\xe2\x60\xe9\xa5' )
        case["ko"] = bytearray( b'\x08\x75\x15\x81\x29\x1d\x5a\x41\x09\xcb' +
                                b'\x10\x24\x4b\x7a\x42\x36\x3f\x0e\x17\x5b' +
                                b'\xce\x0f\xcd\x12\x07\xec\x8a\x5c\xa8\x29' +
                                b'\xd8\x00\x22\x52\x1e\x8d\x0f\xa8\x23\x1c' +
                                b'\xe9\x75\x03\x90\x62\xe1\x74\x4c\xc5\x2c' +
                                b'\xad\x7f\xbd\xc1\x26\x74\x0c\x90\x5b\xbc\x0b\xc4\xa7\x64' )
        self._test_NIST_UseCase( case )
        
    def test_NIST6(self):
        """
         [PRF=HMAC_SHA256]
         [CTRLOCATION=BEFORE_FIXED]
         [RLEN=8_BITS]
         INPUT:
             L = 160
             KI = d68684979908af0812e6b2f065b19ef6b32a148bea5cbb4ae148eb393e66102d
                 FixedInputDataByteLen = 60
                 FixedInputData = 161f7c6a503b60004cf6f0b2486975d7c8a50cbae63590fee366a1cac81f5a36a51181694b3079f03b92c534c134e89274d4a926fbdec0ca579eb43f
                 Binary rep of i = 01
                 instring = 01161f7c6a503b60004cf6f0b2486975d7c8a50cbae63590fee366a1cac81f5a36a51181694b3079f03b92c534c134e89274d4a926fbdec0ca579eb43f
         OUTPUT:
             KO = 9f844f2734268cc2dfddb4354db3a827748ead0f
        """
        case = {"l": 160, "digestmod": hashlib.sha256, "ki": None, "fixedInput": None, "ko": None}
        case["ki"] = bytearray( b'\xd6\x86\x84\x97\x99\x08\xaf\x08\x12\xe6' +
                                b'\xb2\xf0\x65\xb1\x9e\xf6\xb3\x2a\x14\x8b' +
                                b'\xea\x5c\xbb\x4a\xe1\x48\xeb\x39\x3e\x66\x10\x2d' )
        case["fixedInput"] = bytearray( b'\x16\x1f\x7c\x6a\x50\x3b\x60\x00\x4c\xf6' +
                                        b'\xf0\xb2\x48\x69\x75\xd7\xc8\xa5\x0c\xba' +
                                        b'\xe6\x35\x90\xfe\xe3\x66\xa1\xca\xc8\x1f' +
                                        b'\x5a\x36\xa5\x11\x81\x69\x4b\x30\x79\xf0' +
                                        b'\x3b\x92\xc5\x34\xc1\x34\xe8\x92\x74\xd4' +
                                        b'\xa9\x26\xfb\xde\xc0\xca\x57\x9e\xb4\x3f' )
        case["ko"] = bytearray( b'\x9f\x84\x4f\x27\x34\x26\x8c\xc2\xdf\xdd' +
                                b'\xb4\x35\x4d\xb3\xa8\x27\x74\x8e\xad\x0f' )
        self._test_NIST_UseCase( case )
    
    def test_NIST7(self):
        """
        [PRF=HMAC_SHA256]
        [CTRLOCATION=BEFORE_FIXED]
        [RLEN=8_BITS]
        INPUT:
            L = 560
            KI = d2f212cf90659f2069a43e9f7f7b102172470406658d8324b9edff6ac7a7fe52
            FixedInputDataByteLen = 60
            FixedInputData = d2d694e8f4fb4ade0e70d88222742cff975baf6622db8745fcd473793258a97e965feadd5491e4661ff18aa4f398914e9f0ffaf90738f04b158bfe9c
                Binary rep of i = 01
                instring = 01d2d694e8f4fb4ade0e70d88222742cff975baf6622db8745fcd473793258a97e965feadd5491e4661ff18aa4f398914e9f0ffaf90738f04b158bfe9c
                Binary rep of i = 02
                instring = 02d2d694e8f4fb4ade0e70d88222742cff975baf6622db8745fcd473793258a97e965feadd5491e4661ff18aa4f398914e9f0ffaf90738f04b158bfe9c
                Binary rep of i = 03
                instring = 03d2d694e8f4fb4ade0e70d88222742cff975baf6622db8745fcd473793258a97e965feadd5491e4661ff18aa4f398914e9f0ffaf90738f04b158bfe9c
        OUTPUT:
            KO = 0ed1f3374d5bd9fa131af8ec168faae23c4d9e3c5e5788439ced314e8a7e46c4c5eee9ed2c7bb484bd86f99cb97906fd2efd5ffbdcaf0d8dce92f4bbd3f0fd0a79713285557d  
        """
        case = {"l": 560, "digestmod": hashlib.sha256, "ki": None, "fixedInput": None, "ko": None}
        case["ki"] = bytearray( b'\xd2\xf2\x12\xcf\x90\x65\x9f\x20\x69\xa4' +
                                b'\x3e\x9f\x7f\x7b\x10\x21\x72\x47\x04\x06' +
                                b'\x65\x8d\x83\x24\xb9\xed\xff\x6a\xc7\xa7\xfe\x52' )
        case["fixedInput"] = bytearray( b'\xd2\xd6\x94\xe8\xf4\xfb\x4a\xde\x0e\x70' +
                                        b'\xd8\x82\x22\x74\x2c\xff\x97\x5b\xaf\x66' +
                                        b'\x22\xdb\x87\x45\xfc\xd4\x73\x79\x32\x58' +
                                        b'\xa9\x7e\x96\x5f\xea\xdd\x54\x91\xe4\x66' +
                                        b'\x1f\xf1\x8a\xa4\xf3\x98\x91\x4e\x9f\x0f' +
                                        b'\xfa\xf9\x07\x38\xf0\x4b\x15\x8b\xfe\x9c' )
        case["ko"] = bytearray( b'\x0e\xd1\xf3\x37\x4d\x5b\xd9\xfa\x13\x1a' +
                                b'\xf8\xec\x16\x8f\xaa\xe2\x3c\x4d\x9e\x3c' +
                                b'\x5e\x57\x88\x43\x9c\xed\x31\x4e\x8a\x7e' +
                                b'\x46\xc4\xc5\xee\xe9\xed\x2c\x7b\xb4\x84' +
                                b'\xbd\x86\xf9\x9c\xb9\x79\x06\xfd\x2e\xfd' +
                                b'\x5f\xfb\xdc\xaf\x0d\x8d\xce\x92\xf4\xbb' +
                                b'\xd3\xf0\xfd\x0a\x79\x71\x32\x85\x55\x7d' )
        self._test_NIST_UseCase( case )


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()