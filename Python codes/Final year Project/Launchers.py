import shlex
from subprocess import Popen

from scapy.all import *
from scapy.layers.inet import IP

__author__ = 'Bakhtyar'


# TODO Capture files for 60 minute duration, break into 10,20,30...60

def main():
    """
    Main function for Launcher Module
    :return: returns nothing
    """
    hosts = [8, 110, 133, 153, 165, 211]
    hostlist = []
    for host in hosts:
        hostlist.append("192.168.168." + str(host))
    TCPlaunch(hostlist)  #42.0.84


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
        exp = 'hping3 -c 3600 -I wlan0 -1 -C 13 ' + d  # +  ' > /dev/null'
        exp = shlex.split(exp)
        trace = Popen(exp)

    skew = []
    count += 1
    print "Connecting and acquiring fingerprint data for "+str(d)

    ans = sniff(filter='icmp[icmptype] = icmp-tstampreply and host ' + d, count=3600 * len(dest), timeout=1010)
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


def TCPlaunch(dest=['192.168.1.250']):
    """

    :param dest: list of addresses to fingerprint
    :return:
    """
    # rec = unix_time_millis(datetime.datetime.utcfromtimestamp(time.time()-(3600*5+1800)))
    final = []
    s = {}
    count = 0
    for d in dest:
        exp = 'hping3 -c 3600 -I wlan0 -p 139 -k -S --tcp-timestamp ' + d  # +  ' > /dev/null'
        exp = shlex.split(exp)
        trace = Popen(exp)

    skew = []
    count += 1
    print "Connecting and acquiring fingerprint data for " + str(d)

    ans = sniff(filter='icmp[icmptype] = icmp-tstampreply and host ' + d, count=3600 * len(dest), timeout=1010)
    # ans = sniff(filter='icmp[icmptype] = icmp-tstampreply',count=1000,offline="/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand10-icmp.pcap")
    print "Length of ans" + str(len(ans))

    for x in xrange(1, len(ans)):
        RTval = (ans[x].ts_rx - ans[0].ts_rx)
        STval = (ans[x].ts_ori - ans[0].ts_ori)
        skew.append((STval, RTval - STval))

    #            if key in s.keys():
    #                s[key] += 1
    #
    #            else:
    #                s[key] = 1
    final.append(skew)

    return final


def find_and_log():
    for x in xrange(1, 254):
        p = scapy.layers.inet.IP()
        p.src = "192.168.168." + str(x)


if __name__ == '__main__':
    main()
