from base64 import b32decode
from scapy.all import *

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

base32String = ''

for packet in packets[DNS]:
	if(packet.haslayer(DNSQR)):
		if(packet[IP].dst == '10.3.27.86'):
			print('=== Init packet: ===')
			print(packet.show())
			base32String = packet[DNS][1].qname.decode().split('.')[1]
			print('=== Extracted base32 string')
			print(base32String)
			break

print('=== Our flag ===')
print(str(fromBase32(base32String))[2:-3])

