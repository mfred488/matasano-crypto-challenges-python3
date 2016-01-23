import unittest
import itertools
import base64 as b64

from Crypto.Cipher import AES

def fromHex(hexString):
	return b64.b16decode(hexString.upper())

def fromB64(base64String):
	return b64.b64decode(base64String)

def fromAscii(asciiString):
	return bytes(map(ord, asciiString))

def toHex(data):
	return b64.b16encode(data).upper()

def toB64(data):
	return b64.b64encode(data)

def toAscii(data):
	return ''.join(map(chr, data))

def fixedXor(x,y):
	if len(x) != len(y):
		raise Error('Arguments must have the same length')
	res = []
	for i in range(len(x)):
		res += [x[i] ^ y[i]]
	return bytes(res)

def scoreCharacter(c):
	if (ord(c) == 32) or (ord(c) >= 48 and ord(c) <= 59) or (ord(c) >= 63 and ord(c) <= 90) or (ord(c) >= 97 and ord(c) <= 122):
		return 1 # "Normal" characters
	else:
		return 0

def scoreEnglishPlaintext(text):
	return sum(map(scoreCharacter, text))/len(text)

def findSingleXorCharacter(data):
	best, score, bestC = '', -100, -1
	for c in range(255):
		mask = bytes([c for _ in range(len(data))])
		xor = fixedXor(data, mask)
		cScore = scoreEnglishPlaintext(toAscii(xor))
		if cScore > score:
			best, score, bestC = xor, cScore, c
	return toAscii(best), score, bestC

def repeatingKeyXor(key, input):
	if len(key) == 0:
		raise Error('Key must not be empty!')
	i = 0
	res = []
	for x in input:
		res += [x ^ key[i % len(key)]]
		i += 1
	return bytes(res)

def computeHammingWeight(x):
	x = abs(x)
	res = 0
	while x != 0:
		res += x%2
		x //= 2
	return res

def computeHammingDistance(x, y):
	if len(x) != len(y):
		raise Error('Arguments must have the same length')
	return sum([computeHammingWeight(y[i] - x[i]) for i in range(len(x))])

def findKeySizeFromRepeatingXorEncryptedData(data, minSize=3, maxSize=40):
	best, score = 0, 10000
	for keySize in range(minSize, maxSize):
		chunks = [data[i*keySize:(i+1)*keySize] for i in range(20)]
		average = 0
		for x, y in itertools.product(chunks, chunks):
			average += computeHammingDistance(x,y)
		keySizeScore = average / keySize
		if keySizeScore < score:
			best, score = keySize, keySizeScore
	return best

def decryptRepeatingXorEncryptedData(data):
	guessedKeySize = findKeySizeFromRepeatingXorEncryptedData(data)
	slices = [data[i::guessedKeySize] for i in range(guessedKeySize)] # Love that syntax <3
	keyArray = []
	for s in slices:
		r = findSingleXorCharacter(s)
		keyArray += [r[2]]
	key = bytes([findSingleXorCharacter(s)[2] for s in slices])
	return repeatingKeyXor(key, data), key

def isECBEncrypted(data):
	"""We'll consider that the data is ECB-encrypted iof we find twice the same block (block length is assumed to be 16 bytes)"""
	if len(data) % 16 != 0:
		raise Error('Data length must be a multiple of 16 bytes')

	blocks = [data[i*16:(i+1)*16] for i in range(len(data)//16)]
	res = {}
	for b in blocks:
		if b in res:
			return True
		res[b] = True
	return False


class Tester(unittest.TestCase):

	def testChallenge1(self):
		input = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
		output = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
		self.assertEqual(toB64(fromHex(input)), output)

	def testChallenge2(self):
		x = fromHex(b'1c0111001f010100061a024b53535009181c')
		y = fromHex(b'686974207468652062756c6c277320657965')
		output = fromHex(b'746865206b696420646f6e277420706c6179')
		self.assertEqual(fixedXor(x,y), output)

	def testChallenge3(self):
		input = fromHex(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
		output = "Cooking MC's like a pound of bacon"
		result, score, char = findSingleXorCharacter(input)
		self.assertEqual(result, output)

	def testChallenge4(self):
		with open('resources/set1-challenge4.txt', 'r') as testDataFile:
			input = testDataFile.read().splitlines()
			output = [findSingleXorCharacter(fromHex(l)) for l in input]
			output.sort(key=lambda r: r[1], reverse=True)
			self.assertEqual(output[0][0], 'Now that the party is jumping\n')

	def testChallenge5(self):
		input = fromAscii("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
		key = fromAscii('ICE')
		output = fromHex(b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
		self.assertEqual(repeatingKeyXor(key, input), output)

	def testChallenge6(self):
		with open('resources/set1-challenge6.txt', 'r') as testDataFile:
			input = fromB64(testDataFile.read().replace('\n', ''))
			clearData, key = decryptRepeatingXorEncryptedData(input)
			self.assertIn(b"I'm back and I'm ringin' the bell", clearData)

	def testChallenge7(self):
		with open('resources/set1-challenge7.txt', 'r') as testDataFile:
			input = fromB64(testDataFile.read().replace('\n', ''))
			clearData = AES.new(b'YELLOW SUBMARINE').decrypt(input)
			self.assertIn(b"I'm back and I'm ringin' the bell", clearData)

	def testChallenge8(self):
		with open('resources/set1-challenge8.txt', 'r') as testDataFile:
			input = testDataFile.read().splitlines()
			ecbEncryptedData = [hexData if isECBEncrypted(fromHex(hexData)) else None for hexData in input]
			ecbEncryptedDataNumber = 0
			for result in filter(lambda x: x, ecbEncryptedData):
				ecbEncryptedDataNumber += 1 # Annoying way to test the size of the filtered result (filter returns an iterator)
			self.assertEqual(ecbEncryptedDataNumber, 1)

if __name__ == '__main__':
	unittest.main()