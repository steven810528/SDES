
class sdes(object):
	__key = [0,0,0,0,0,0,0,0,0,0]
	
	#key func used to change the order 
	__p10 = [3,5,2,7,4,10,1,9,8,6]
	__p8 = [6,3,7,4,8,5,10,9]
	
	#__left_rotations[1,2]
	
	#plaintxt_used using in the start and end
	__ip = [2,6,3,1,4,8,5,7]
	__fp = [4,1,3,5,7,2,8,6]
	#to porlong the key size from 4 to 8 
	__expansion_table = [4,1,2,3,2,3,4,1]
	#
	__sbox1 = [[1,0,3,2],
		  [3,2,1,0],
		  [0,2,1,3],
		  [3,1,3,2]]
	__sbox2 = [[0,1,2,3],
		  [2,0,1,3],
		  [3,0,1,0],
		  [2,1,0,3]]
	__p4 = [2,4,3,1]
	
	# contract
	def __init(self, key):
		# Sanity checking of arguments.
		if key >1023 or key <0:
			raise ValueError("Key's size need to between 0 and 1023")
		

		#attribute
		self.key_size = 10
		self.L = []
		self.R = []
		self.Kn = [ [0] * 8 ] * 2	# 2 8-bits keys (K1,K2),subkey
		self.final = []

		self.setKey(key)
	#set key, 
	def setKey(self, key):
		self.__key=bin(key)
		#self.__create_sub_keys()

	#creat sub key
	def __create_sub_keys(self):
		i = 0
		# Split into Left and Right sections
		self.L = key[:6] #0~5
		self.R = key[6:] #6~10
		
	# permutate func
	def __permutate(self, table, block):
		"""Permutate the data block with the specified table"""
		return list(map(lambda x: block[x], table))
	# convert string to bits
	
