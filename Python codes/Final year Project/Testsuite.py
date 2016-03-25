__author__ = 'bakhtyar'
import os

from pylab import figure, show

import Comparator
import Type1Utilities as Df


def test_dr_vs_capture_time(start, end, interval, type):
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


def test1_detection_rate_vs_num_devices(type, signature_directory, test_directory):
    # todo type 1 test1
    if type == 1:
        for

    if type == 2:
        pass
        # todo type 2 test1
    if type == 3:
        pass
        # todo type 3 test1
    if type == 4:
        pass
        # todo type 4 test1


def TPR_vs_FNG():
    pass


def main():
    test_different_bin_intervals(0, 10000, 1000)


if __name__ == '__main__':
    main()
