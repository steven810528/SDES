import sys
sys.path.insert(0, "/Users/steven/SDES")
from pySDES import *
k = sdes("1023")
#k.printKeyBits()

d=k.encrypt("My test data")
k.decrypt()
#print(d)
#k.decrypt(d)
