__author__ = 'bakhtyar'
import os

from pylab import figure, show

import AddToDB
import Comparator
import Type1Utilities as Df


def addAll(lim):
    folder = os.listdir("TestDumps/Type1/")
    for name in folder:
        if name[-4:] == 'pcap':
            sig, status = Df.Generator("TestDumps/Type1/" + str(name), lim)
            AddToDB.add2Db(name[:-5], sig, 1)
    AddToDB.printDBkeys()


def test_Type1_Different_Bin_Intervals(start, end, interval, type):
    """
    Test signatures with different bin sizes
    :param start:
    :param end:
    :param interval:
    :return:
    """
    if type == 1:
        xAxis = [x for x in xrange(start, end, interval)]
        y1 = []
        y2 = []
        FP = []
        for x in xrange(start, end, interval):
            lim = x
            truePositive = 0
            falsePositive = 0
            # AddToDB.purgeDB()
            # addAll(lim)
            folder = os.listdir("TestDumps/Type1/")
            for name in folder:
                if name[-4:] == 'pcap':
                    sig, status = Df.Generator("TestDumps/Type1/" + str(name), lim)
                    match, matchSig = Comparator.findMatchingSignature(sig, 1)
                    if match == name[:-5]:
                        truePositive += 1
                    else:
                        falsePositive += 1
                        FP.append((match, name[:-5]))
            y1.append(truePositive)
            y2.append(falsePositive)
        print xAxis
        print y1
        print y2
        print(FP)
        fig = figure(1)
        ax1 = fig.add_subplot(121)
        ax2 = fig.add_subplot(122)
        ax1.plot(xAxis, y1, '-b')
        ax2.plot(xAxis, y2, '-r')
        ax1.grid(True)
        ax1.set_ylim(0, max(y1) + 5)
        ax1.set_ylabel('True Positives')
        ax1.set_xlabel('Time')
        ax1.set_title('True Positives')
        ax2.grid(True)
        ax2.set_ylim(0, max(y2) + 5)
        ax2.set_ylabel('False Positives')
        ax2.set_xlabel('Time')
        ax2.set_title('False Positives')
        show()
        return
    elif type == 2:
        pass
        # Todo type 2 binning
    elif type == 3:
        pass
        # Todo type 3 binning


def Detection_Rate_VS_Num_of_Devices():
    pass


def TPR_vs_FNG():
    pass


def main():
    test_Type1_Different_Bin_Intervals(0, 10000, 1000)


if __name__ == '__main__':
    main()