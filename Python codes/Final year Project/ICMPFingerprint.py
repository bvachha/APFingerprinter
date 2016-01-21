__author__ = 'Bakhtyar'

import binascii
import dpkt
from scapy.all import *
from scapy.layers.inet import *
from decimal import *
import Skewer
import ICMPLauncher

getcontext().prec = 9  # Set precision of the decimal values to 9

def ByteOrderCheck(dumppath):
    count = 0
    f = open(dumppath)  # Open pcap file
    pc = dpkt.pcap.Reader(f)  # Read data from the file into pc
    testarr = []
    for ts, rawdata in pc:
        if count > 5:
            break
        tap = dpkt.ethernet.Ethernet(rawdata)	# Format as a Ethernet packet
        ipdata = tap.data	# Extract Ip Data
        icmpdata = ipdata.data	# Extract ICMP data
        testarr.append(int(binascii.hexlify(icmpdata.data[-4:]),16))
        count += 1
    for x in xrange(4):
        if abs(testarr[x]-testarr[x+1]>5000):
            print True
            return True
    print False
    return False


def ICMPSkewGenerator(dumppath):
    """
    Function to generate a list of coordinates corresponding to the skew
    :param dumppath: Path of the dump file
    :param reversal: if set takes the timestamp to be in network byte order
    :return:
    """
    #Todo set a flag or a test to verify the ordering of the timestamp :DONE
    reversal = ByteOrderCheck(dumppath)
    print ("Creating skew list for file: " + dumppath)
    sysclkinit = ''  # Initial system clock value
    rclkinit = ''  # Initial remote clock value
    skew = []  # List of skews
    f = open(dumppath)  # Open pcap file
    pc = dpkt.pcap.Reader(f)  # Read data from the file into pc

    for ts, rawdata in pc:
        tap = dpkt.ethernet.Ethernet(rawdata)	# Format as a Ethernet packet
        ipdata = tap.data	# Extract Ip Data
        icmpdata = ipdata.data	# Extract ICMP data

        if reversal == True:    #Timestamp follows Network Byte Order

            if rclkinit == '':	# Set initial values
                sysclkinit = int(binascii.hexlify(icmpdata.data[-12:-8]), 16)   #Set initial Sender timestamp
                rclkinit = []

                for i in xrange(len(icmpdata.data) - 4, len(icmpdata.data)):
                    rclkinit.append(binascii.hexlify(icmpdata.data[i]))

                rclkinit = "".join(reversed(rclkinit))
                rclkinit = int(rclkinit,16)
                sclk=sysclkinit
                rclk=rclkinit

            else:
                sclk = int(binascii.hexlify(icmpdata.data[-12:-8]), 16)
                rclk = [binascii.hexlify(icmpdata.data[i])for i in xrange(len(icmpdata.data)-4,len(icmpdata.data))]
                rclk = "".join(reversed(rclk))
                rclk = int(rclk,16)

            print "STHex="+str(sclk)
            RTval = rclk - rclkinit	#Extract Remote clock values
            STval = sclk - sysclkinit	#Extract system clock values
            skew.append((STval, RTval-STval))

        else:

            if rclkinit == '':	# Set initial values
                sysclkinit = int(binascii.hexlify(icmpdata.data[-12:-8]), 16)
                rclkinit = int(binascii.hexlify(icmpdata.data[-4:]), 16)
                sclk=sysclkinit
                rclk=rclkinit

            else:
                sclk = int(binascii.hexlify(icmpdata.data[-12:-8]), 16)
                rclk = int(binascii.hexlify(icmpdata.data[-4:]), 16)

            RTval = rclk - rclkinit	#Extract Remote clock values
            STval = sclk - sysclkinit	#Extract system clock values
            skew.append((STval, RTval-STval))

    print skew
    return skew


def main():
    skew = []
    #skew = ICMPLauncher.ICMPlaunch(['192.168.28.25'])
    ByteOrderCheck("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand1-icmp.pcap")
    ByteOrderCheck("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/3c77e68d0805.pcap")
    skew.append(ICMPSkewGenerator("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand3-icmp.pcap"))
    skew.append(ICMPSkewGenerator("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand4-icmp.pcap"))
    skew.append(ICMPSkewGenerator("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand6-icmp.pcap"))
    skew.append(ICMPSkewGenerator("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/3c77e68d0805.pcap"))
    skew.append(ICMPSkewGenerator("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/0c60763ea14e.pcap"))
    Skewer.drawSkewGraph(skew)


if __name__ == '__main__':
    main()
#ToDO Some of the skews are spreading out due to network order of timestamps