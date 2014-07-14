# -*- coding: utf-8 -*- 
'''
Created on 14/07/2014

@author: Aitor Gomez Goiri
'''

import base64
from hmac import HMAC

class NIST(object):
    
    def set_hmac(self, digestmod, secret):
        assert secret != None, "Key derivation key cannot be null.";
        self.hmac = HMAC(secret, digestmod=digestmod)
            
    # Calculate the size of a key. The key size is given in bits, but we can
    # only allocate them by octets (i.e., bytes), so make sure we round up to
    # the next whole number of octets to have room for all the bits. For
    # example, a key size of 9 bits would require 2 octets to store it.
    # @param ks
    #    The key size, in bits.
    # @return The key size, in octets, large enough to accommodate {@code ks}
    #         bits.
    def _calc_key_size(self, ks):
        assert ks > 0, "Key size must be > 0 bits."
        n = ks / 8
        rem = ks % 8
        return n if rem==0 else n+1
    
    def _to_one_byte(self, inByte):
        assert isinstance( inByte, int ), "This method expected an int as a parameter"
        assert inByte<128, "The maximum value of ctr is 127 (1 byte only)"
        output = bytearray()
        output.append(inByte)
        return output;
    
    def derive_key(self, outputSizeBits, fixedInput):
        assert outputSizeBits >= 56, "Key has size of %d, which is less than minimum of 56-bits." % outputSizeBits
        assert (outputSizeBits % 8) == 0, "Key size (%d) must be a even multiple of 8-bits." % outputSizeBits
        
        outputSizeBytes = self._calc_key_size(outputSizeBits); # Safely convert to
                                                        # whole # of bytes.
        derivedKey = [] #bytearray()
                
        # Repeatedly call of HmacSHA1 hash until we've collected enough bits
        # for the derived key.
        ctr = 1 # Iteration counter for NIST 800-108
        totalCopied = 0
        destPos = 0
        lenn = 0
        tmpKey = None
        
        while True: # ugly translation of do-while
            self.hmac.update( self._to_one_byte(ctr) );
            ctr += 1 # note that the maximum value of ctr is 127 (1 byte only)
                                            
            # According to the Javadoc for Mac.doFinal(byte[]),
            # "A call to this method resets this Mac object to the state it was
            # in when previously initialized via a call to init(Key) or
            # init(Key, AlgorithmParameterSpec). That is, the object is reset
            # and available to generate another MAC from the same key, if
            # desired, via new calls to update and doFinal." Therefore, we do
            # not do an explicit reset() and don't need to feed KDK again?
            self.hmac.update(fixedInput) #doFinal(fixedInput);
            tmpKey = self.hmac.hexdigest() # in str, but not in python format (e.g u'\xab\x02')!
            # pretty sure that using digest() I could "save" the half of the bytes used,
            # but then I don't know how to make the copy at byte level
            print bytearray(self.hmac.digest())
            
            if len(tmpKey) >= outputSizeBytes:
                lenn = outputSizeBytes;
            else:
                lenn = min(len(tmpKey), outputSizeBytes - totalCopied);
            
            #System.arraycopy(tmpKey, 0, derivedKey, destPos, lenn);
            derivedKey[destPos:destPos+lenn] = tmpKey[:lenn*2]
            totalCopied += len(tmpKey)
            destPos += lenn
            
            if totalCopied >= outputSizeBytes: # ugly translation of do-while
                break
        
        #return derivedKey
        ret = ""
        for i in range(0, len(derivedKey), 2):
            ret += "/x%s%s" % (derivedKey[i], derivedKey[i+1])
        return ret