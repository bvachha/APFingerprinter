from scapy.layers.inet import IP,ICMP, TCP
from scapy.sendrecv import send
from scapy import all
import random

import time

__author__ = 'Bakhtyar'



def main():
    for x in xrange(0,100):
		#millis = int(round(time.time() * 1000))
		#print millis
        send(IP(dst = "192.168.1.80") /ICMP(type=13,id=x))
        time.sleep(1)

def randomizer():
    dest = "127.0.0.1"
    #n = input("Enter the number of packets")
    for x in xrange(0,500):
        first = random.randint(1,255)
        second = random.randint(1,255)
        third = random.randint(1,255)
        fourth = random.randint(1,255)
        source = str(224)+"."+str(second)+"."+str(third)+"."+str(fourth)
        send(IP(src=source, dst = dest) /TCP(sport= 80,dport=80, flags = 'S'))
    print str(source)+" packets sent"



if __name__ == '__main__':
    main()
