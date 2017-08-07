#!/usr/bin/env python
#SHA2017 CTF | Cryptography [Stack Overflow - 100 pts]
#@Abdelkader 
 
import os, sys
from Crypto.Cipher import AES
from itertools import *

fn = sys.argv[1]
data = open(fn+'.enc','rb').read()

# Secure CTR mode encryption using random key and random IV, taken from
# http://stackoverflow.com/questions/3154998/pycrypto-problem-using-aesctr
secret = os.urandom(16)
crypto = AES.new(os.urandom(32), AES.MODE_CTR, counter=lambda: secret) 

#encrypted = crypto.encrypt(data)
decrypted = crypto.decrypt(data)
#open(fn+'.enc','wb').write(encrypted)
open(fn,'wb').write(decrypted)

#2nd part

h = [243, 186, 253, 51, 29, 40, 68, 168, 37, 32, 222, 183, 222, 12, 111, 185]
encrypt = open("flag.pdf.enc", "rb").read()
decrypt = open("flag.pdf", "wb")

for i,j in zip(encrypt, cycle(h)):
	decrypt.write(chr(int(i.encode("hex"), 16) ^ j))
