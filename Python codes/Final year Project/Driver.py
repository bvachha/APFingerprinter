__author__ = 'bakhtyar'
import DriverFingerprint as Df
import AddToDB
import ICMPFingerprint
import Comparator
import DrawSignature
import Skewer
import os


from scapy.all import *
import ClusterTest

def addAll(lim):
    folder = os.listdir("TestDumps/")
    for name in folder:
        if name[-4:] == 'pcap':
            sig = Df.Generator("TestDumps/" + str(name), lim)
            AddToDB.add2Db(name[:-5], sig)
    AddToDB.printDBkeys()


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def main():
    #dump = rdpcap("TestDumps/Dell1.pcap")  # Store data in dump
    #print "Dumpfile Created Succesfully"
    #for x in xrange(len(dump)):
     #   print dump[x].timestamp
    #Testing.test(100,1000,50)
    #AddToDB.purgeDB()
    #AddToDB.addAll(800)
    #sig = Df.Generator("TestDumps/ProbeReqs2(Dlink).pcap",800)
    #if sig == 0:
    #    return
    #print "---------------------------------------------------------------------------------------"
    #dump = rdpcap("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/NITRCS.pcap")
    max_d = 1
    skew = []
    
    #skew.append(Skewer.skewfilterDpkt("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/DinkLab.pcap"))
    #skew.append(Skewer.skewfilterDpkt("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Hostel1.pcap"))
    #skew.append(Skewer.skewfilterDpkt("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Hostel1.pcap"))
    #skew.append(Skewer.skewfilterDpkt("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/LabCap.pcap"))
    #skew.append(Skewer.skewfilterDpkt("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Device1.pcap"))
    #skew.append(Skewer.skewfilterDpkt("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type2/Device4.pcap"))
    skew.append(ICMPFingerprint.ICMPSkewGenerator("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/0c60763ea14e.pcap"))
    print skew[0]
    Skewer.drawSkewGraph(skew)
    ClusterTest.dendrogramMaker(skew[0],max_d)
    ClusterTest.DBCluster(skew[0],max_d)
    
    #temp = skew[0]
    #n = len(temp)/5
    #print n
    #multi = list(chunks(temp,n))
    #Skewer.drawSkewGraph(skew)
    #AddToDB.printDBkeys()
    #AddToDB.purgeDB()
    #AddToDB.removeFromDB('Azurewav:a3:52:d5.pcap')
    #AddToDB.add2Db("74:04:2b:41:8e:dd", sig)
    #AddToDB.printDBkeys()

    #match,matchSig = Comparator.findMatch(sig)
    #DrawSignature.DrawSig1(sig)

if __name__ == '__main__':
    main()
