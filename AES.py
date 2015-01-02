import re
import math

pattern = re.compile(r"\s+")

Nk = 4
Nb = 4
Nr = 10

Rcon = []
rijndael_sbox = []
inverse_rijndael_sbox = []

#Prints the state
def PrintState(state):
	for i in range(0, Nb):
		for j in range(0, Nb):
			print state[i][j],
#end PrintState

#Adds leading zeroes to a hex value
def AddLeadingZeroes(word, size):
	diff = size - len(word)
	for i in range(0, diff):
		word = "0" + word
	return word
#end AddLeadingZeroes


#Substitutes the rotated word for the word in the sbox
def SubWord(rotword):
	
	subword = ""
	for i in range(0, len(rotword)):
		if(i % 2 == 0):
			subword += rijndael_sbox[int(rotword[i], 16)][int(rotword[i+1], 16)]

	subword = re.sub(pattern, "", subword)
	return subword
#end SubWord


#Rotates the leftmost byte to the rightmost position
#@param:	temp	the word to rotate
def RotWord(temp):
	temp = temp[2:] + temp[:2]
	temp = re.sub(pattern, "", temp)
	return temp
#end RotWord

#Generates the round keys
#@param:	key		an array that stores the cipherkey
#@param:	w		an array to store the round keys	 
def KeyExpansion(key, w):
	temp = ""
	i = 0
	
	while(i < Nk):
		w.append(key[4*i] + key[4*i + 1] + key[4*i + 2] + key[4*i + 3])
		i = i + 1
	
	i = Nk

	while(i < Nb*(Nr + 1)):
		temp = w[i - 1]
		if(i % Nk == 0):
			rotword = RotWord(temp)
			subword = SubWord(rotword)
			temp = int(subword, 16) ^ int(Rcon[int((math.floor(i/Nk) - 1))], 16)
			temp = '{:x}'.format(temp)
			temp = AddLeadingZeroes(temp, 8)
		word = int(w[i - Nk], 16) ^ int(temp, 16)
		word = '{:x}'.format(word)
		word = AddLeadingZeroes(word, 8)
		w.append(word)

		i = i + 1
#end KeyExpansion

#XORs each column of the state with a word in the key schedule
def AddRoundKey(state, w_subset):
	c = 0
	for word in w_subset:
		word = re.sub(pattern, "", word)
		r = 0
		for i in range(0, len(word)):
			subword = ""
			if(i % 2 == 0):
				subword = word[i:i+2]
				#xor the values
				value = int(subword, 16) ^ int(state[c][r], 16)
				value = '{:x}'.format(value)
				value = AddLeadingZeroes(value, 2)
				state[c][r] = value
				r = r + 1
		c = c + 1
#end AddRoundKey

#each value in the state is substituted by it's corresponding value
#in the s-box
def SubBytes(state):
	for i in range(0, 4):
		for j in range(0, 4):
			value = state[i][j]
			row = int(value[:1], 16)
			col = int(value[1:], 16)
			state[i][j] = rijndael_sbox[row][col]
			state[i][j] = re.sub(pattern, "", state[i][j])
#end SubBytes
	
#shifts the rows of the state
def ShiftRows(state):

	#shift 2nd row by 1 position
	temp = state[0][1]
	state[0][1] = state[1][1]
	state[1][1] = state[2][1]
	state[2][1] = state[3][1]
	state[3][1] = temp

	#shift 3rd row by 2 positions
	temp = state[0][2]
	temp2 = state[1][2]
	state[0][2] = state[2][2]
	state[1][2] = state[3][2]
	state[2][2] = temp
	state[3][2] = temp2

	#shift 4th row by 3 positions
	temp = state[3][3]
	state[3][3] = state[2][3]
	state[2][3] = state[1][3]
	state[1][3] = state[0][3]
	state[0][3] = temp
#end ShiftRows

#the mix columns transformation on the state
def MixColumns(state):
	
	irreducible_poly = 27 		#1b in hex (the irreducible polynomial value)
	overflow_value = 256 		#2^8
	multiplier = [3, 1, 1, 2]	#the multipliers
	
	for i in range(0, Nb):
		temp_state = []
		shifter = 0
		for j in range(0, Nb):
			#temp stores all values to be XORed
			temp = []
			for k in range(0, Nb):
				#a multiplier of 3 does a multiply by 1 and a multiply by 2
				if(multiplier[(k+shifter)%len(multiplier)] == 3):
					value = int(state[i][k], 16) * 1
					temp.append(value)
					value = int(state[i][k], 16) * 2
					#if overflows, add irreducible polynomial to temp
					if(value >= overflow_value):
						value = value - overflow_value
						temp.append(value)
						temp.append(irreducible_poly)
					else:
						temp.append(value)
				else:
					value = int(state[i][k], 16) * multiplier[(k+shifter)%len(multiplier)]
					if(value >= overflow_value):
						value = value - overflow_value
						temp.append(value)
						temp.append(irreducible_poly)
					else:
						temp.append(value)

			xor_temp = temp[0]
			for t in range(1, len(temp)):
				xor_temp = xor_temp ^ temp[t]
			xor_temp = '{:x}'.format(xor_temp)
			xor_temp = AddLeadingZeroes(xor_temp, 2)
			shifter = shifter + 1

			temp_state.append(xor_temp)

		#put updated values in state
		for l in range(0, Nb):
			state[i][l] = temp_state[(Nb-1)-l]
#end MixColumns

#the encryption process
def Cipher(state, w):
	print "\nEncryption Process:\n"
	print "Plaintext:"
	PrintState(state)

	AddRoundKey(state, w[:Nb])

	print "\nRound 1:"
	PrintState(state)

	for round in range(1, Nr):
		SubBytes(state)
		ShiftRows(state)
		MixColumns(state)
		AddRoundKey(state, w[(round*Nb):((round+1)*Nb)])

		print "\n\nRound %d:" % (round+1)
		PrintState(state)

	SubBytes(state)
	ShiftRows(state)
	AddRoundKey(state, w[(Nr*Nb):(Nr+1)*Nb])

	print "\n\nCiphertext:"
	PrintState(state)
#end Cipher

#inversely shifts the rows
def InvShiftRows(state):

	#shift 2nd row by 1 position
	temp = state[3][1]
	state[3][1] = state[2][1]
	state[2][1] = state[1][1]
	state[1][1] = state[0][1]
	state[0][1] = temp

	#shift 3rd row by 2 positions
	temp = state[3][2]
	temp2 = state[2][2]
	state[3][2] = state[1][2]
	state[2][2] = state[0][2]
	state[1][2] = temp
	state[0][2] = temp2

	#shift 4th row by 3 positions
	temp = state[0][3]
	state[0][3] = state[1][3]
	state[1][3] = state[2][3]
	state[2][3] = state[3][3]
	state[3][3] = temp
#end InvShiftRows

#substitutes the values in the state for it's corresponding value in
#the inverse s-box
def InvSubBytes(state):
	for i in range(0, Nb):
		for j in range(0, Nb):
			value = state[i][j]
			row = int(value[:1], 16)
			col = int(value[1:], 16)
			state[i][j] = inverse_rijndael_sbox[row][col]
			state[i][j] = re.sub(pattern, "", state[i][j])
#end InvSubBytes

#the inverse mix columns transformation
def InvMixColumns(state):

	#values for the irreducible polynomials
	irreducible_x8 = 27 #1b in hex
	irreducible_x9 = 54 #36 in hex
	irreducible_x10 = 108 #6c in hex
	irreducible_x11 = 216 #d8 in hex
	
	#values for the overflow bits
	overflow_bit8 = 256 #2^8
	overflow_bit9 = 512
	overflow_bit10 = 1024
	overflow_bit11 = 2048
	
	#values for the multipliers
	m1 = int("0e", 16)
	m2 = int("0b", 16)
	m3 = int("0d", 16)
	m4 = int("09", 16)
	multiplier = [m2, m3, m4, m1]
	
	factors = [1, 2, 4, 8, 16, 32, 64, 128]

	for i in range(0, Nb):
		temp_state = []
		shifter = 0
		for j in range(0, Nb):
			xor = []
			for k in range(0, Nb):
				pos = []
				adder = []
				temp = []
				state_value = int(state[i][k], 16)	
				if(state_value != 0):
					#find the positions of the 1s
					for f in range(0, len(factors)):
						if((state_value & factors[f]) == factors[f]):
							pos.append(f)
					#get the "adders" that result from the mutliplication
					for p in range(0, len(pos)):
						to_add = multiplier[(k+shifter)%len(multiplier)] * math.pow(2, pos[p])
						adder.append(int(to_add))	
					for value in adder:	
						#add any irreducible polynomials if there is overflow		
						if(value >= overflow_bit8):
							if((value ^ overflow_bit8) == (value - overflow_bit8)):
								value =	value - overflow_bit8
								temp.append(irreducible_x8)
							if((value ^ overflow_bit9) == (value - overflow_bit9)):
								value = value - overflow_bit9
								temp.append(irreducible_x9)
							if((value ^ overflow_bit10) == (value - overflow_bit10)):
								value = value - overflow_bit10
								temp.append(irreducible_x10)
							if((value ^ overflow_bit11) == (value - overflow_bit11)):
								value = value - overflow_bit11
								temp.append(irreducible_x11)
						temp.append(value)
				
					#XOR to get one of the products
					xor_temp = temp[0]
					for t in range(1, len(temp)):
						xor_temp = xor_temp ^ temp[t]
					xor.append(xor_temp)
				else:
					xor.append(0)
					
			#XOR the "products"
			xor_temp = xor[0]
			for x in range(1, len(xor)):
				xor_temp = xor_temp ^ xor[x]
		
			shifter = shifter + 1
			xor_temp = '{:x}'.format(xor_temp)
			xor_temp = AddLeadingZeroes(xor_temp, 2)
			temp_state.append(xor_temp)
		
		#store updated values in the state
		for l in range(0, Nb):
			state[i][l] = temp_state[(Nb-1)-l]
#end InvMixColumns

#the inverse cipher function	
def InvCipher(state, w):

	print "\n\n\nDecryption Process:"
	print "\nCiphertext:"
	PrintState(state)

	AddRoundKey(state, w[(Nr*Nb):(Nr+1)*Nb])

	for round in range((Nr-1), 0, -1):
		InvShiftRows(state)
		InvSubBytes(state)
	
		print "\n\nRound %d:" % round
		PrintState(state)
	
		AddRoundKey(state, w[(round*Nb):(round+1)*Nb])
		InvMixColumns(state)

	InvShiftRows(state)
	InvSubBytes(state)
	
	print "\n\nRound 0:"
	PrintState(state)

	AddRoundKey(state, w[0:Nb])

	print "\n\nPlaintext:"
	PrintState(state)
#end InvCipher

#mainline
def main():
	#the following is the "main()" function:
	f = open("aes_sbox.txt", "r")
	row = []
	counter = 0

	#read and store values of aes sbox into a 2d array
	for line in f:
		line = re.sub(pattern, "", line)
		for i in range(0, len(line)/2):
			row.append(line[(i*2):(i*2)+2])
		counter = counter + 1
		if(counter == 2):
			rijndael_sbox.append(row)
			row = []
			counter = 0

	#read and store values of inverse aes sbox into a 2d array
	f = open("aes_inv_sbox.txt", "r")
	row = []
	counter = 0

	for line in f:
		line = re.sub(pattern, "", line)
		for i in range(0, len(line)/2):
			row.append(line[(i*2):(i*2)+2])
		counter = counter + 1
		if(counter == 2):
			inverse_rijndael_sbox.append(row)
			row = []
			counter = 0
			
	#generate Rcon
	Rcon.append("01000000")
	init = int("01000000", 16)
	for i in range(0, 11):
		if(int(Rcon[i], 16) == int("80000000", 16)):
			Rcon.append("1b000000")
		else:
			temp = int(Rcon[i], 16) * 2
			temp = '{:x}'.format(temp)
			Rcon.append(temp) 
			
	key_files = ["test1key.txt", "test2key.txt", "test3key.txt"]
	plaintext_files = ["test1plaintext.txt", "test2plaintext.txt", "test3plaintext.txt"]

	for f1, f2 in zip(key_files, plaintext_files):
		#read and store key and plaintext file contents
		f = open(f1, "r")
		key = []

		for line in f:
			cipherkey = line.split(" ")
			for c in cipherkey:
				key.append(c)
		
		f = open(f2, "r")
		state = []
		plaintext = ""

		for line in f:
			plaintext = line.split(" ")
	
		x = []
		for p in plaintext:
			x.append(p)
			if(len(x) == Nb):
				state.append(x)
				x = []
	
		w = []
		KeyExpansion(key, w)

		print "\nKey Schedule:"
		for i in range(0, len(w)):
			print "w[%d] = %s" % (i, w[i])

		Cipher(state, w)
		InvCipher(state, w)	
		
		print "\n"	
			
if __name__ == '__main__':
	main()
