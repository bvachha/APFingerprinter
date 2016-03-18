from scapy.all import *

import AddToDB
import Comparator
import Type1Utilities
import Type3Utilities

__author__ = 'bakhtyar'


# !/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Fingerprinter(Revised).py
#
#  Copyright 2015 bakhtyar <bakhtyar@Inspiron-3537>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#

def addAll(lim):
    folder = os.listdir("TestDumps/")
    for name in folder:
        if name[-4:] == 'pcap':
            sig = Type1Utilities.Generator("TestDumps/" + str(name), lim)
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
    """Type1"""
    # test,status = DriverFingerprint.Generator("TestDumps/Type1/001b77671742().pcap",lim = 10000)
    # print Comparator.findMatchingSignature(test,1)[0]
    # skew.append(Skewer.skew_generator_DPKT("TestDumps/Hostel1.pcap"))
    # skew.append(Skewer.skew_generator_DPKT("TestDumps/Hostel1.pcap"))
    # skew.append(Skewer.skew_generator_DPKT("TestDumps/LabCap.pcap"))
    # skew.append(Skewer.skew_generator_DPKT("TestDumps/Device1.pcap"))
    """Type 2"""
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/94fbb2dddbfc_3.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/80a1d7e0c06a(bxghosh).pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/80a1d7e0c06a(bxghosh)1.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/80a1d7e0c06b(MGMNT).pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/80a1d7e0c06b(MGMNT)1.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/0cd2b51c0490(Anir).pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/0cd2b51c0490(Anir)1.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/0cd2b51c0490(Anir)2.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/0cd2b50351ac(BinaTone).pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/0cd2b50351ac(BinaTone)1.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/CiscoLi(virus308).pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/CiscoLi(virus308)-1.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/CiscoLi(virus308)-2.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/CiscoLi(virus308)-3.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/CiscoLi(virus308)-4.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/CiscoLi(virus308)-5.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/CiscoLi(virus308)-6.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/CiscoLi(virus308)-7.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/Virus.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/Shenzen1.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/Tenda 2.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/MSNLB.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/TKC.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/Device2.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/Device3.pcap"))
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/CiscoLi(virus308)-7.pcap"))


    # Test = Type2Utilities.create_Type2_Signature("TestDumps/Type2/CiscoLi(virus308)-1.pcap")
    # skew.append(Type2Utilities.skew_generator_DPKT("TestDumps/Type2/54b80a95ce07(QorqlBSNL)_1.pcap"))
    # AddToDB.purgeDB()
    # AddToDB.printDBkeys()
    # AddToDB.addAll("TestDumps/Type2/",2)
    # Comparator.findMatchingSignature(Test,2)
    """Type 3"""
    # AddToDB.purgeDB()
    Test = Type3Utilities.create_type4_signature("TestDumps/Type3/TCPopts/303a645fb9c3.pcap")
    # AddToDB.addAll("/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/TCPopts/",4)
    AddToDB.printDBkeys()
    Comparator.findMatchingSignature(Test, 4)

    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/0c60763ea14e.pcap",binning = True))
    # ---skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/2c56dc06f5d3.pcap"))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/3c77e68d0805.pcap",binning = False))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Asus2.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Asus2-1.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Asus3.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Asus3-1.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Dell1.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Dell1-2.pcap",binning = True))
    # ---skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Dell2.pcap",binning = False))
    # ---skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Dell2-1.pcap",binning = False))

    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand1-icmp.pcap",binning = True)) #Dev1
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand2-icmp.pcap",binning = True)) #dev2
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand2-test.pcap",binning = True))
    # ---skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand-icmp.pcap",binning = True))
    # ---skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand5-icmp.pcap",binning = False))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand6-icmp.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand7-icmp.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand8-icmp.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand8-test.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand9-icmp.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand9-test.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand10-icmp.pcap",binning = True)) #dev3
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand10-test.pcap",binning = False))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand11-icmp.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Rand11-test.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Samsung1.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Samsung2.pcap",binning = True)) #Dev 4
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Samsung3.pcap",binning = False))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/Samsung3-1.pcap",binning = True)) #dev5
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/SonyE1.pcap",binning = False))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/SonyE1-2.pcap",binning = True))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/SonyE2.pcap",binning = False))
    # skew.append(Type3utilities.ICMPSkewGenerator("TestDumps/Type3/SonyE2-1.pcap",binning = False))
    # skew.append(ICMPFingerprint.ICMPSkewGenerator("TestDumps/Type3/Samsung2.pcap"))

    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/DellWindows.pcap",binning = True,SIncr=1000))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/DeviceRouter.pcap",binning = True))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/MacbookAir.pcap",binning = True,SIncr=1000))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/DevTest.pcap",binning = True))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/Dev1.pcap",binning = True))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/Dev2.pcap",binning = True))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/Dev3.pcap",binning = False))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/Dev4.pcap",binning = False))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/Dev5.pcap",binning = False))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/Dev6.pcap",binning = False,SIncr=1000))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/lib1.pcap",binning = True))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/lib2.pcap",binning = True,SIncr=1000))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/lib3.pcap",binning = True))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/lib4.pcap",binning = True))
    # skew.append(Type3utilities.TCPSkewGenerator("TestDumps/Type3/TCPopts/lib5.pcap",binning = True))

    # for skews in skew:
    #    for x in xrange(20):
    #        print skews[x]
    # Type2Utilities.drawSkewGraph(skew)
    # ClusterTest.dendrogramMaker(skew[0],max_d)
    # ClusterTest.DBCluster(skew[0],max_d)

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
