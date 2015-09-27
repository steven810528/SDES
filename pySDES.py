
import sys

# _pythonMajorVersion is used to handle Python2 and Python3 differences.
_pythonMajorVersion = sys.version_info[0]

# Modes of crypting / cyphering
ECB =	0
CBC =	1

# Modes of padding
PAD_NORMAL = 1
PAD_PKCS5 = 2

# PAD_PKCS5: is a method that will unambiguously remove all padding
#            characters after decryption, when originally encrypted with
#            this padding mode.
# For a good description of the PKCS5 padding technique, see:
# http://www.faqs.org/rfcs/rfc1423.html

# The base class shared by des and triple des.
class _baseDes(object):
	def __init__(self, mode=ECB, IV=None, pad=None, padmode=PAD_PKCS5):
		# Check IV and pad to make sure they only contain ASCII unicode characters
		if IV:
			IV = self._guardAgainstUnicode(IV)
		if pad:
			pad = self._guardAgainstUnicode(pad)

		# Block size is a byte
		self.block_size = 1		

		# Sanity checking of arguments.
		if pad and padmode == PAD_PKCS5:
			raise ValueError("Cannot use a pad character with PAD_PKCS5")
		if IV and len(IV) != self.block_size:
			raise ValueError("Invalid Initial Value (IV), must be a multiple of " + str(self.block_size) + " bytes")

		# Set the passed in variables
		self._mode = mode
		self._iv = IV
		self._padding = pad
		self._padmode = padmode

	def getKey(self):
		"""getKey() -> bytes"""
		return self.__key

	def setKey(self, key):
		"""Key between 0 and 1023"""
		self.__key = key

	def getMode(self):
		"""getMode() -> pyDes.ECB or pyDes.CBC"""
		return self._mode

	def setMode(self, mode):
		"""Sets the type of crypting mode, pyDes.ECB or pyDes.CBC"""
		self._mode = mode

	def getPadding(self):
		"""getPadding() -> bytes of length 1. Padding character."""
		return self._padding

	def setPadding(self, pad):
		"""setPadding() -> bytes of length 1. Padding character."""
		if pad is not None:
			pad = self._guardAgainstUnicode(pad)
		self._padding = pad

	def getPadMode(self):
		"""getPadMode() -> pyDes.PAD_NORMAL or pyDes.PAD_PKCS5"""
		return self._padmode
		
	def setPadMode(self, mode):
		"""Sets the type of padding mode, pyDes.PAD_NORMAL or pyDes.PAD_PKCS5"""
		self._padmode = mode

	def getIV(self):
		"""getIV() -> bytes"""
		return self._iv

	def setIV(self, IV):
		"""Will set the Initial Value, used in conjunction with CBC mode"""
		if not IV or len(IV) != self.block_size:
			raise ValueError("Invalid Initial Value (IV), must be a multiple of " + str(self.block_size) + " bytes")
		IV = self._guardAgainstUnicode(IV)
		self._iv = IV

	def _padData(self, data, pad, padmode):
		# Pad data depending on the mode
		if padmode is None:
			# Get the default padding mode.
			padmode = self.getPadMode()
		if pad and padmode == PAD_PKCS5:
			raise ValueError("Cannot use a pad character with PAD_PKCS5")

		if padmode == PAD_NORMAL:
			if len(data) % self.block_size == 0:
				# No padding required.
				return data

			if not pad:
				# Get the default padding.
				pad = self.getPadding()
			if not pad:
				raise ValueError("Data must be a multiple of " + str(self.block_size) + " bytes in length. Use padmode=PAD_PKCS5 or set the pad character.")
			data += (self.block_size - (len(data) % self.block_size)) * pad
		
		elif padmode == PAD_PKCS5:
			pad_len = 1 - (len(data) % self.block_size)
			if _pythonMajorVersion < 3:
				data += pad_len * chr(pad_len)
			else:
				data += bytes([pad_len] * pad_len)

		return data

	def _unpadData(self, data, pad, padmode):
		# Unpad data depending on the mode.
		if not data:
			return data
		if pad and padmode == PAD_PKCS5:
			raise ValueError("Cannot use a pad character with PAD_PKCS5")
		if padmode is None:
			# Get the default padding mode.
			padmode = self.getPadMode()

		if padmode == PAD_NORMAL:
			if not pad:
				# Get the default padding.
				pad = self.getPadding()
			if pad:
				data = data[:-self.block_size] + \
				       data[-self.block_size:].rstrip(pad)

		elif padmode == PAD_PKCS5:
			if _pythonMajorVersion < 3:
				pad_len = ord(data[-1])
			else:
				pad_len = data[-1]
			data = data[:-pad_len]

		return data

#############################################################################
# 				    SDES					    					
#
#############################################################################
class sdes(_baseDes):
	keyInt = -1
	keyBits= [0,0,0,0,0,0,0,0,0,0]
	key_after_p10 = [0,0,0,0,0,0,0,0,0,0]
	keyL = [0,0,0,0,0]
	keyR = [0,0,0,0,0]
	
	subkey1 = [0,0,0,0,0,0,0,0,0,0]
	subkey2 = [0,0,0,0,0,0,0,0,0,0]

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
	
	# Type of crypting being done
	ENCRYPT =	0x00
	DECRYPT =	0x01

	# Initialisation
	def __init__(self, key, mode=ECB, IV=None, pad=None, padmode=PAD_PKCS5):
		# Sanity checking of arguments.
		if int(key) < 0 or int(key) >1023 :
			raise ValueError("Invalid SDES key . Key must be a integer between 0 and 1023")
		self.keyInt = key
		_baseDes.__init__(self, mode, IV, pad, padmode)
		self.key_size = 10

		self.L = []
		self.R = []
		self.Kn = [ [0] * 8 ] * 2	# 16 48-bit keys (K1 - K16)
		self.final = []

		self.setKey(int(key))

	#set the key and create two subkeys
	def setKey(self, key):
		# Will set the crypting key for this object. Must be 8 bytes.
		_baseDes.setKey(self, key)
		self.int_To_Bits(int(key))
		#self.create_sub_keys()
		
		#permutate(self.__p10, self.keyBits, self.key_after_p10)
		n = 9
	 	i = 0
		for i in range(n) :
			self.key_after_p10[i]= self.keyBits[self.__p10[i]-1]
		n = 5
		i= 0
		#cut the key to 2 
		for i in range(n) :
			self.keyR [i]= self.key_after_p10[i]
			self.keyL [i]= self.key_after_p10[i+5]
		#left rotaion to R and L
		self.left_shift_key()

		#create subkey using P8
		tmp = [0,0,0,0,0,0,0,0,0,0]
		i = 0
		n = 5
		for i in range(n):
			tmp[i]=self.keyR[i]
			tmp[i+5]= self.keyL[i]		
		i = 0
		n = 8
		for i in range(n):
			self.subkey1[i]= tmp[self.__p8[i]-1]

		#left rotation to R and L again
		self.left_shift_key()


		#create subkey2 using P8
		tmp = [0,0,0,0,0,0,0,0,0,0]
		i = 0
		n = 5
		for i in range(n):
			tmp[i]=self.keyR[i]
			tmp[i+5]= self.keyL[i]		
		i = 0
		n = 8
		for i in range(n):
			self.subkey2[i]= tmp[self.__p8[i]-1]

				
	#change the integer to 8 bits
	def int_To_Bits(self, num):
		i = 0
		x =num
		for i in range(9):
			self.keyBits[9-i]= x%2
			x = int(x /2)

	#print the keybits
	def printKeyBits(self):		
		st = 'show the process\n'
	
		i=0
		st+='\nthe orginal key:'
		st+=str(self.keyInt)+'\n'

		for i in range(10):
			st+= str(self.keyBits[i])
		
		i = 0
		st+= '\nthe key after P10:\n'
		for i in range(10):
			st+= str(self.key_after_p10[i])
		
		i = 0
		st+= '\nthe subkey1:\n'
		for i in range(8):
			st += str(self.subkey1[i])

		i = 0
		st+= '\nthe subkey2:\n'
		for i in range(8):
			st+=str(self.subkey2[i])
			
		print(st)
		
	def left_shift_key(self):
		R0 = self.keyR[0]
		L0 = self.keyL[0]
		n = 4
		i = 0
		for i in range(n):
			self.keyR[i]= self.keyR[i+1]
			self.keyL[i]= self.keyL[i+1]
		self.keyR[4]= R0
		self.keyL[4]= L0
		#print('run left rotation')

	"""
	#change the order by table
	def permutate(self, table , block , output):
		n = 10
	 	i = 1
		for i in range(n) :
			output[i]= block[table[i]]
	"""



########################################################################################


##########################       handle plain txt     ##################################


########################################################################################

	c_byte=[0]

	#the main function
	def crypt(self,data, crypt_type):
		if not data:
			return 'no data'
		if crypt_type == sdes.ENCRYPT:
			return self.encrypt(data)
		if crypt_type == sdes.DECRYPT:
			return self.decrypt()


	#the encrypt func call the subfunc
	def encrypt(self, data):
		#convet data to num
		print('start encrypt')
		print(data)
		
		data = [ord(c) for c in data]

		self.printArray(data)
		i = 0
		n = len(data)
		outpute=[0]*n
		#call sub and handle every char in data 
		for i in range(n):
			outpute[i]= self.encrypt_sub(data[i])
		#return self.crypt(data, sdes.ENCRYPT)
		self.c_byte=outpute
		
		self.printArray(outpute)
		
		st=''.join([ chr(c) for c in outpute ])

		#i = 0
		#for i in range(n):
		#	st.join(chr(outpute[i])
		print(st)
		return st
	#convert c_byte to string
	def decrypt(self):
		print('start decrypt')
		self.printArray(self.c_byte)
		i = 0	
		n = len(self.c_byte)
		outpute=[0]*n
		for i in range(n):
			outpute[i]=self.decrypt_sub(self.c_byte[i])
		self.printArray(outpute)
		#convert bits to num
		
		st=''.join([ chr(c) for c in outpute ])
		print(st)
		return st

	def decrypt_sub(self, byte):
		after_fp_reverse = [0]*8
		charbits=[0]*8
		i=0
		charbits = self.charnum_to_bits(byte)
		#__fp's reverse
		for i in range(8):
			after_fp_reverse[self.__fp[i]-1]=charbits[i] 
		L=after_fp_reverse[0:4]
		R = after_fp_reverse[4:8]
		R_fk = self.functionK(R,self.subkey2)
		R_original=[0]*4
		i = 0
		for i in range(4):
			if L[i]==R_fk[i]:
				R_original[i]= 0 
			else:
				R_original[i]= 1
		R_fk = self.functionK(R_original,self.subkey1)
		i = 0
		L_original=[0]*4
		for i in range(4):
			if R[i]==R_fk[i]:
				L_original[i]= 0 
			else:
				L_original[i]= 1
		outpute=[0]*8
		outpute[0:4]=L_original
		outpute[4:8]=R_original
		
		after_ip_reverse= [0]*8
		i = 0 
		for i in range(8):
			after_ip_reverse[self.__ip[i]-1]=outpute[i]
		
		return self.bits_to_int(after_ip_reverse)

	def encrypt_sub(self, charnum):
		after_ip = [0]*8
		i = 0
		charbits = [0]*8
		charbits = self.charnum_to_bits(charnum)
		#self.printArray(charbits)
		#self.printArray(self.__ip)
		for i in range(8):
			after_ip [i]= charbits[self.__ip[i]-1]
				
		L = after_ip[:4]
		R = after_ip[4:]
		
		#put R into fk, first round
		R_fk =  self.functionK(R , self.subkey1)
		i = 0

		#self.printArray(R_fk)

		for i in range(4):
			if L[i]==R_fk[i]:
				L[i]=0
			else:
				L[i]=1
		#self.printArray(L)
		#put L into fk ,second round
		L_fk = self.functionK(L,self.subkey2)

		#self.printArray(L_fk)

		i = 0 
		for i in range(4):
			if R[i]==L_fk[i]:
				R[i]=0
			else :
				R[i]=1

		#self.printArray(R)

		output=[0]*8
		output[:4]=R
		output[4:]=L
		output_fp = [0]*8
		i = 0
		for i in range(8):
			output_fp[i]=output[self.__fp[i]-1]

		#convert bits to int
		#print('point')
		#self.printArray(output_fp)
		return self.bits_to_int(output_fp)

		#fk , dataR only 4 bits
	def functionK(self, dataL , key):
		tmp = [0]*8
		tmpR = [0]*4
		tmpL = [0]*4
		#prolong the 4 bits to 8 bits
		i = 0 
		n = 8
		for i in range(n):
			tmp [i]= dataL[self.__expansion_table[i]-1]
		#XOR with key 1 or 2
		i = 0
		for i in range(n):
			if(tmp[i]==key[i]):
				tmp[i]= 0
			else :
				tmp[i]=1
		#cut tmp to L and R
		tmpR = tmp[0:4]
		tmpL = tmp[4:8]
		#get R and L from sbox

		R = self.__sbox1[self.bits_to_int(tmpR[0:2]) ][self.bits_to_int(tmpR[2:4]) ]
		L = self.__sbox2[self.bits_to_int(tmpL[0:2]) ][self.bits_to_int(tmpL[2:4]) ]
		
		tmp[1]=R%2
		tmp[0]=int(R/2)
		tmp[3]=L%2
		tmp[2]=int(L/2)
		
		tmp_after_p4=[0]*4
		i=0
		n=4
		for i in range(n):
			tmp_after_p4[i]=tmp[self.__p4[i]-1]
		
		return tmp_after_p4 

	#according to the len and convert bits to integer
	def bits_to_int(self,bits):
		num = 0
		i = 0
		n= len(bits)
		for i in range(n):
			num+= bits[i]* 2**((n-i)-1)
		return num

	#anscio to 8 bits
	def charnum_to_bits(self, charnum):
		num = charnum
		i = 0 
		n = 8
		bits = [0]*8
		for i in range(n):
			bits[7-i]= num % 2
			num = int(num /2)
		return bits
	def printArray(self,array):
		n = len(array)
		st = ''
		i = 0
		for i in range(n):
			st+=str(array[i])
			st+=' '
		print(st)
	

