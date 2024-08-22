all: arp-spoof

arp-spoof: arp-spoof.c
		gcc -o arp-spoof arp-spoof.c -lpcap

