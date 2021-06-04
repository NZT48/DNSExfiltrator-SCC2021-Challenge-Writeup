from base64 import b32decode
from scapy.all import *
import zipfile


#------------------------------------------------------------------------
# Class providing RC4 encryption/decryption functions
#------------------------------------------------------------------------
class RC4:
	def __init__(self, key = None):
		self.state = list(range(256))
		self.x = self.y = 0

		if key is not None:
			self.key = key
			self.init(key)

	# Key schedule
	def init(self, key):
		for i in range(256):
			self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
			self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
		self.x = 0

	# Decrypt binary input data
	def binaryDecrypt(self, data):
		output = [None]*len(data)
		for i in range(len(data)):
			self.x = (self.x + 1) & 0xFF
			self.y = (self.state[self.x] + self.y) & 0xFF
			self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
			output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
		return bytearray(output)

#------------------------------------------------------------------------

def fromBase32(msg):
	# Base32 decoding, we need to add the padding back
	# Add padding characters
	mod = len(msg) % 8
	if mod == 2:
		padding = '======'
	elif mod == 4:
		padding = '===='
	elif mod == 5:
		padding = '==='
	elif mod == 7:
		padding = '='
	else:
		padding = ''

	return b32decode(msg.upper() + padding)

#------------------------------------------------------------------------

packets = rdpcap('challengeDNS_anon.pcapng')

base32Strings = []
joinedStrings = ''

for packet in packets[DNS]:
	if(packet.haslayer(DNSQR)):
		if(packet[IP].dst == '10.3.27.86'):
			# Uncomment line below to see packet structure
			#print(packet.show())
			base32Strings.append(packet[DNS][1].qname.decode())


for i in range(1,len(base32Strings)):
	if i % 2 == 0:
		joinedStrings += ''.join(base32Strings[i].split('.')[1:-3])

print('=== Encrypted file in base32 ===')
print(joinedStrings)


# Save data to a file
outputFileName = 'solution.zip'

print('=== Guessing password for RC4 ===')
with open(outputFileName, 'wb+') as fileHandle:
	letter = 'a'
	for i in range(1,25):
		print(f'Trying with {letter*3} as password.')
		rc4Decryptor = RC4(letter*3)
		decryptedData = rc4Decryptor.binaryDecrypt(bytearray(fromBase32(joinedStrings)))
		if(chr(decryptedData[0]) == 'P' and chr(decryptedData[1]) == 'K'):
			print(f'Bingo, password is {letter*3}!')
			fileHandle.write(decryptedData)
			break
		letter = chr(ord(letter) + 1)
	
with zipfile.ZipFile('solution.zip', 'r') as zip_ref:
    zip_ref.extractall('./')

print('=== File sent over the network ===')
with open('pWduMpF1le.fl4g','r') as file:
	print(file.read())

