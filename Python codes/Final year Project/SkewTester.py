import Type2Utilities

__author__ = 'bakhtyar'

def main():
    skew = []
    # kew.append(Skewer.skew_generator_DPKT("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Catatonic.pcap"))
    skew = (Type2Utilities.skew_generator_DPKT(
        "/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type2/Device2.pcap"))
    print skew

#    interval = len(skew)/4
#    print len(skew)
#    print interval
#    chunks=[skew[x:x+interval] for x in xrange(0, len(skew), interval)]
#    for x in xrange(len(chunks)):
#        starttime1 = chunks[x][0][0]
#        starttime2 = chunks[x][0][1]
#        for y in xrange(len(chunks[x])):
#            chunks[x][y][0] = chunks[x][y][0]- starttime1
#            chunks[x][y][1] = chunks[x][y][1]- starttime2
#        print chunks[x][0:20]

    # skew.append(Skewer.skew_generator_DPKT("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Device3.pcap"))
    # skew.append(Skewer.skew_generator_DPKT("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Device1.pcap"))
    # skew.append(Skewer.skew_generator_DPKT("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Device2.pcap"))
    Type2Utilities.drawSkewGraph([skew])


if __name__ == '__main__':
    main()
