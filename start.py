import sys
sys.path.insert(0, "/Users/steven/SDES")
from pyDES import *
k = des("DESCRYPT")
d=k.encrypt("test data")
print(d)
k.decrypt(d)
