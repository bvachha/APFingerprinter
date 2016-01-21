from scapy.all import *
import shlex
from scapy.layers.inet import ICMP, IP
from subprocess import Popen
import datetime

__author__ = 'Bakhtyar'


def main():
    """
    Main function for Launcher Module
    :return: returns nothing
    """
    ICMPlaunch(['192.168.43.143','192.168.1.126','192.168.1.87'])#42.0.84


def ICMPlaunch(dest=['192.168.1.250']):
    """

    :param dest: list of addresses to fingerprint
    :return:
    """
    #rec = unix_time_millis(datetime.datetime.utcfromtimestamp(time.time()-(3600*5+1800)))
    final = []
    s = {}
    count = 0
    for d in dest:
        exp = 'hping3 -c 1000 -I wlan0 -1 -C 13 '+d  # +  ' > /dev/null'
        exp = shlex.split(exp)
        trace = Popen(exp)

    skew = []
    count += 1
    print "Connecting and acquiring fingerprint data for "+str(d)

    ans = sniff(filter='icmp[icmptype] = icmp-tstampreply and host '+d ,count=1001*len(dest),timeout=1010)
    #ans = sniff(filter='icmp[icmptype] = icmp-tstampreply',count=1000,offline="/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand10-icmp.pcap")
    print "Length of ans" +str(len(ans))

    for x in xrange(1, len(ans)):
        RTval=(ans[x].ts_rx - ans[0].ts_rx)
        STval=(ans[x].ts_ori - ans[0].ts_ori)
        skew.append((STval, RTval-STval))

#            if key in s.keys():
#                s[key] += 1
#
#            else:
#                s[key] = 1
    final.append(skew)

    return final


if __name__ == '__main__':
    main()
