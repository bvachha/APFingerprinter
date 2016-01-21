__author__ = 'bakhtyar'

import AddToDB
#TODO Add comparision mechanism for clock skews generated
#TODO Use a threshold to decide when a device deviates too much from stored device signatures


def compare(test, signature):  # Finds the closeness measure between test and signature
    """
    Compares the test and signature tuples and returns the closeness measure
    :param test: signature tuple being compared
    :param signature: stored signature to be compared
    :return: closeness measure value
    """
    result = 0
    end = min(len(test), len(signature))
    for x in xrange(0, end-1):
        result += (abs(test[x][1] - signature[x][1] ) + signature[x][1] * abs(test[x][2] - signature[x][2]))
    return result


def findMatch(test):
    minCloseness = 99999999999999
    result = ''
    DataBase = AddToDB.getDB()
    for key in DataBase.keys():
        closeness = compare(test, DataBase[key])
        print key
        print closeness
        print"=========================================================="
        if closeness < minCloseness:
            minCloseness = closeness
            result = key
            resultSig = DataBase[key]
    print "The matching device is:"+str(result)
    return result, resultSig
