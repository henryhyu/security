# CS177 -- padding oracle attacks This code is (unfortunately) meant
# to be run with Python 2.7.10 on the CSIL cluster
# machines. Unfortunately, cryptography libraries are not available
# for Python3 at present, it would seem.
from Crypto.Cipher import AES
import binascii
import sys

def check_enc(text):
    nl = len(text)
    val = int(binascii.hexlify(text[-1]), 16)
    if val == 0 or val > 16:
        return False

    for i in range(1,val+1):
        if (int(binascii.hexlify(text[nl-i]), 16) != val):
            return False
    return True
                                 
def PadOracle(ciphertext):
    if len(ciphertext) % 16 != 0:
        return False
    
    tkey = 'Sixteen byte key'

    ivd = ciphertext[:AES.block_size]
    dc = AES.new(tkey, AES.MODE_CBC, ivd)
    ptext = dc.decrypt(ciphertext[AES.block_size:])

    return check_enc(ptext)


# Padding-oracle attack comes here

if len(sys.argv) > 1:
    myfile = open(sys.argv[1], "r")
    ctext=myfile.read()
    myfile.close()

    res = ""
    alldata = bytearray(ctext)
    block = []
    
    for i in range (0, len(alldata)/16-1):
        block.append(alldata[i*16:32+(i*16)])
    for currentblock in block:
        currentRes = ""
        for process in range (1,17):
            default = currentblock[16 - process]
            for i in range (0,256):
                currentblock[16 - process] = i ^ process
                if (PadOracle(str(currentblock))):
                    currentRes = chr(default ^ i) + currentRes
                    # caveat situation
                    if (process == 1):
                        rightBit = currentblock[15]
                        leftBit = currentblock[14]
                        for j in range(i + 1, 256):
                            currentblock[15] = j ^ process
                            if(PadOracle(str(currentblock))):
                                currentblock[14] = currentblock[14] + 1
                                if(PadOracle(str(currentblock))):
                                    currentblock[14] = leftBit
                                else:
                                    currentblock[14] = leftBit
                                    currentblock[15] = rightBit
                                break
                            if(j == 255):
                                currentblock[15] = rightBit
                    for k in range(0, process):
                        currentblock[15-k] = currentblock[15-k] ^ process ^ process+1
                    break
        res += currentRes
    print res
                    
                


    

    
    # complete from here. The ciphertext is now (hopefull) stored in
    # ctext as a string. Individual symbols can be accessed as
    # int(ctext[i]). Some more hints will be given on the Piazza
    # page.


    # end completing here, leave rest unchanged.
else:
    print("You need to specify a file!")
    
