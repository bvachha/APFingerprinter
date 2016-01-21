from scapy.sendrecv import sniff

__author__ = 'bakhtyar'
import AddToDB
import DriverFingerprint as Df
import os
import Comparator
from pylab import figure, show

def addAll(lim):
    folder = os.listdir("TestDumps/")
    for name in folder:
        if name[-4:] == 'pcap':
            sig = Df.Generator("TestDumps/" + str(name), lim)
            AddToDB.add2Db(name[:-5], sig)
    AddToDB.printDBkeys()


def test(start, end, interval):
    xAxis = [x for x in xrange(start,end,interval)]
    y1 = []
    y2 = []
    FP = []
    for x in xrange(start,end,interval):
        lim = x
        truePositive = 0
        falsePositive = 0
        AddToDB.purgeDB()
        addAll(lim)
        folder = os.listdir("TestDumps/TestCases/")
        for name in folder:
            if name[-4:] == 'pcap':
                sig = Df.Generator("TestDumps/TestCases/" + str(name), lim)
                match,matchSig = Comparator.findMatch(sig)
                if match == name[:-5]:
                    truePositive += 1
                else:
                    falsePositive += 1
                    FP.append((match,name[:-5]))
        y1.append(truePositive)
        y2.append(falsePositive)
    print xAxis
    print y1
    print y2
    print(FP)
    fig = figure(1)
    ax1 = fig.add_subplot(121)
    ax2 = fig.add_subplot(122)
    ax1.plot(xAxis, y1,'-b')
    ax2.plot(xAxis, y2,'-r')
    ax1.grid(True)
    ax1.set_ylim(0, max(y1)+5)
    ax1.set_ylabel('True Positives')
    ax1.set_xlabel('Time')
    ax1.set_title('True Positives')
    ax2.grid(True)
    ax2.set_ylim(0, max(y2)+5)
    ax2.set_ylabel('False Positives')
    ax2.set_xlabel('Time')
    ax2.set_title('False Positives')
    show()
    return


def Filtering(src, dst, type):
    dump = sniff(filter="",offline=)
