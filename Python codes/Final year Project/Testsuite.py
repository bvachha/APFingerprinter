import os

from pylab import figure, show

import AddToDB
import Comparator
import Type1Utilities
import Type2Utilities
import Type3Utilities

__author__ = 'bakhtyar'


def test1_detection_rate_vs_num_devices(type, signature_directory, test_directory):
    """
    Test the matching characteristics for types of
    :param type:
    :param signature_directory:
    :param test_directory:
    :return:
    """
    # todo type 1 test1
    if type == 1:
        x_axis = [0]
        y1 = [0]
        y2 = [0]
        FP = []
        signature_folder = os.listdir(signature_directory)
        for name in signature_folder:
            if name[-4:] == 'pcap':
                truepositive = 0
                falsepositive = 0
                sig, status = Type1Utilities.create_type1_signature(signature_directory + str(name), lim=500)
                AddToDB.add2Db(name[:-5], sig, 1)
                db_dump = AddToDB.getDB()
                test_folder = os.listdir(test_directory)
                for testcase in test_folder:
                    if testcase[-4:] == 'pcap' and testcase[:12] in db_dump.keys():
                        print testcase
                        test, status = Type1Utilities.create_type1_signature(test_directory + str(testcase), lim=500)
                        match = Comparator.findMatchingSignature(test, 1)
                        if match == testcase[:12]:
                            truepositive += 1
                        else:
                            falsepositive += 1
                        FP.append((match, testcase[:12]))
                x_axis.append(x_axis[-1] + 1)
                y1.append(truepositive)
                y2.append(falsepositive)
        print x_axis
        print y1
        print y2
        print FP
        fig = figure(1)
        ax1 = fig.add_subplot(121)
        ax2 = fig.add_subplot(122)
        ax1.plot(x_axis, y1, '-b')
        ax2.plot(x_axis, y2, '-r')
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

    if type == 2:
        x_axis = [0]
        y1 = [0]
        y2 = [0]
        FP = []
        signature_folder = os.listdir(signature_directory)
        for name in signature_folder:
            if name[-4:] == 'pcap':
                truepositive = 0
                falsepositive = 0
                sig = Type2Utilities.create_Type2_Signature(signature_directory + str(name))
                AddToDB.add2Db(name[:12], sig, 2)
                db_dump = AddToDB.getDB()
                test_folder = os.listdir(test_directory)

                for testcase in test_folder:
                    if testcase[-4:] == 'pcap' and testcase[:12] in db_dump.keys():

                        test = Type2Utilities.create_Type2_Signature(test_directory + str(testcase))
                        print db_dump
                        print test
                        match = Comparator.findMatchingSignature(test, 2)
                        if match == testcase[:12]:
                            truepositive += 1
                        else:
                            falsepositive += 1
                        FP.append((match, testcase[:12]))
                x_axis.append(x_axis[-1] + 1)
                y1.append(truepositive)
                y2.append(falsepositive)
        print x_axis
        print y1
        print y2
        print FP
        fig = figure(1)
        ax1 = fig.add_subplot(121)
        ax2 = fig.add_subplot(122)
        ax1.plot(x_axis, y1, '-b')
        ax2.plot(x_axis, y2, '-r')
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

    if type == 3:
        pass
        # todo type 3 test1

    if type == 4:
        # todo type 4 test1
        x_axis = [0]
        y1 = [0]
        y2 = [0]
        FP = []
        signature_folder = os.listdir(signature_directory)
        for name in signature_folder:
            if name[-4:] == 'pcap':
                truepositive = 0
                falsepositive = 0
                sig = Type3Utilities.create_type4_signature(signature_directory + str(name))
                AddToDB.add2Db(name[:12], sig, 4)
                db_dump = AddToDB.getDB()
                test_folder = os.listdir(test_directory)
                for testcase in test_folder:
                    if testcase[-4:] == 'pcap' and testcase[:12] in db_dump.keys():

                        test = Type3Utilities.create_type4_signature(test_directory + str(testcase))
                        match = Comparator.findMatchingSignature(test, 4)
                        if match == testcase[:12]:
                            truepositive += 1
                        else:
                            falsepositive += 1
                        FP.append((match, testcase[:12]))
                x_axis.append(x_axis[-1] + 1)
                y1.append(truepositive)
                y2.append(falsepositive)
        print x_axis
        print y1
        print y2
        print FP
        fig = figure(1)
        ax1 = fig.add_subplot(121)
        ax2 = fig.add_subplot(122)
        ax1.plot(x_axis, y1, '-b')
        ax2.plot(x_axis, y2, '-r')
        ax1.grid(True)
        ax1.set_ylim(0, max(y1) + 5)
        ax1.set_ylabel('True Positives')
        ax1.set_xlabel('Number of Devices')
        ax1.set_title('True Positives')
        ax2.grid(True)
        ax2.set_ylim(0, max(y2) + 5)
        ax2.set_ylabel('False Positives')
        ax2.set_xlabel('Number of Devices')
        ax2.set_title('False Positives')
        show()


def test3_dr_vs_capture_time(start, end, interval, type):
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
                    sig, status = Type1Utilities.create_type1_signature("TestDumps/Type1/" + str(name), lim)
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


def test4_dr_vs_traffic_size():
    pass


def TPR_vs_FNG():
    pass


def main():
    AddToDB.purgeDB()
    test1_detection_rate_vs_num_devices(4, "TestDumps/Type4/for_signature/", "TestDumps/Type4/for_testing/")


if __name__ == '__main__':
    main()
