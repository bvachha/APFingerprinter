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
                sig = Type2Utilities.create_type2_signature(signature_directory + str(name))
                AddToDB.add2Db(name[:12], sig, 2)
                db_dump = AddToDB.getDB()
                test_folder = os.listdir(test_directory)

                for testcase in test_folder:
                    if testcase[-4:] == 'pcap' and testcase[:12] in db_dump.keys():

                        test = Type2Utilities.create_type2_signature(test_directory + str(testcase))
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
    :return: nothing
    """

    if type == 1:
        xAxis = [x for x in xrange(start, end, interval)]
        y1 = []
        y2 = []
        FP = []
        AddToDB.addAll("TestDumps/Type1/for_signatures/", 1)
        for x in xrange(start, end, interval):
            lim = x
            truePositive = 0
            falsePositive = 0
            folder = os.listdir("TestDumps/Type1/for_testing/")
            for name in folder:
                if name[-4:] == 'pcap':
                    sig = Type1Utilities.create_type1_signature("TestDumps/Type1/for_testing/" + str(name), lim)
                    match = Comparator.findMatchingSignature(sig, 1)
                    if match == name[:12]:
                        truePositive += 1
                    else:
                        falsePositive += 1
                    FP.append((match, name[:12]))
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
        ax1.set_xlabel('Capture Size')
        ax1.set_title('True Positives')
        ax2.grid(True)
        ax2.set_ylim(0, max(y2) + 5)
        ax2.set_ylabel('False Positives')
        ax2.set_xlabel('Capture Size')
        ax2.set_title('False Positives')
        show()

    elif type == 2:  # Todo type 2 binning test
        xAxis = [x for x in xrange(start, end, interval)]
        y1 = []
        y2 = []
        FP = []
        AddToDB.addAll("TestDumps/Type2/for_signatures/", 2)
        for x in xrange(start, end, interval):
            capture_size = x
            truePositive = 0
            falsePositive = 0
            folder = os.listdir("TestDumps/Type2/for_testing/")
            for name in folder:
                if name[-4:] == 'pcap':
                    sig = Type2Utilities.create_type2_signature("TestDumps/Type2/for_testing/" + str(name),
                                                                size=capture_size)
                    match = Comparator.findMatchingSignature(sig, 2)
                    if match == name[:12]:
                        truePositive += 1
                    else:
                        falsePositive += 1
                    FP.append((match, name[:12]))
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
        ax1.set_ylim(min(y1) - 5, max(y1) + 5)
        ax1.set_ylabel('True Positives')
        ax1.set_xlabel('Capture Size')
        ax1.set_title('True Positives')
        ax2.grid(True)
        ax2.set_ylim(min(y2) - 5, max(y2) + 5)
        ax2.set_ylabel('False Positives')
        ax2.set_xlabel('Capture Size')
        ax2.set_title('False Positives')
        show()



    elif type == 4:  # Todo type 4 binning
        xAxis = [x for x in xrange(start, end, interval)]
        y1 = []
        y2 = []
        FP = []
        AddToDB.addAll("TestDumps/Type4/for_signatures/", 4)
        for x in xrange(start, end, interval):
            capture_size = x
            truePositive = 0
            falsePositive = 0
            folder = os.listdir("TestDumps/Type4/for_testing/")
            for name in folder:
                if name[-4:] == 'pcap':
                    sig = Type3Utilities.create_type4_signature("TestDumps/Type4/for_testing/" + str(name),
                                                                size=capture_size)
                    match = Comparator.findMatchingSignature(sig, 4)
                    if match == name[:12]:
                        truePositive += 1
                    else:
                        falsePositive += 1
                        FP.append((match, name[:12]))
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
        ax1.set_ylim(min(y1) - 5, max(y1) + 5)
        ax1.set_ylabel('True Positives')
        ax1.set_xlabel('Capture Size')
        ax1.set_title('True Positives')
        ax2.grid(True)
        ax2.set_ylim(min(y2) - 5, max(y2) + 5)
        ax2.set_ylabel('False Positives')
        ax2.set_xlabel('Capture Size')
        ax2.set_title('False Positives')
        show()


def test4_dr_vs_traffic_size():
    pass


def test5_tpr_vs_threshold():
    pass


def test6_fpr_vs_threshold():
    pass



def main():
    # AddToDB.purge_Type(2)
    # test1_detection_rate_vs_num_devices(4, "TestDumps/Type4/for_signatures/", "TestDumps/Type4/for_testing/")
    test3_dr_vs_capture_time(100, 1000, 100, 4)

if __name__ == '__main__':
    main()
