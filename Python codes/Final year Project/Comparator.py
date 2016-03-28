import operator
from decimal import Decimal
from math import *

import AddToDB

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

#TODO Add comparision mechanism for clock skews generated
#TODO Use a threshold to decide when a device deviates too much from stored device signatures

def euclidean_distance(x, y):
    return sqrt(sum(pow(a - b, 2) for a, b in zip(x, y)))


def manhattan_distance(x, y):
    return sum(abs(a - b) for a, b in zip(x, y))


def nth_root(value, n_root):
    root_value = 1 / float(n_root)
    return round(Decimal(value) ** Decimal(root_value), 3)


def minkowski_distance(x, y, p_value):
    return nth_root(sum(pow(abs(a - b), p_value) for a, b in zip(x, y)), p_value)


def square_rooted(x):
    return round(sqrt(sum([a * a for a in x])), 3)


def cosine_similarity(x, y):
    numerator = sum(a * b for a, b in zip(x, y))
    denominator = square_rooted(x) * square_rooted(y)
    return round(numerator / float(denominator), 3)


def jaccard_similarity(x, y):
    intersection_cardinality = len(set.intersection(*[set(x), set(y)]))
    union_cardinality = len(set.union(*[set(x), set(y)]))
    return intersection_cardinality / float(union_cardinality)


def compareType1(test, signature):
    """
    Compares the test and signature tuples and returns the closeness measure
    :param test: signature tuple being compared
    :param signature: stored signature to be compared
    :return: closeness measure value
    """
    result = 0
    end = min(len(test), len(signature))
    for x in xrange(0, end-1):
        result += (abs(test[x][1] - signature[x][1]) + signature[x][1] * abs(test[x][2] - signature[x][2]))
    return result


def compareType2(test, signature):  # TODO type 2 comparator
    pass


def compareType3(test, signature):  # TODO type 3 comparator
    pass


def findMatchingSignature(test, type, threshold=999999):
    # ToDo implement type based matching
    """
    Tries to find the closest matching signature in the database
    :param test: The signature that needs to be checked
    :return:
    """
    result = 'No Match!'
    if type == 1:
        print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
        print "In Signature match module"
        minCloseness = threshold
        resultSig = []
        DataBase = AddToDB.getDB()
        for key in DataBase.keys():
            if DataBase[key][1] == 1:
                # print "Testing device " + str(key)
                closeness = compareType1(test, DataBase[key][0])
                if closeness < minCloseness:
                    minCloseness = closeness
                    result = key
                    resultSig = DataBase[key]
                    print"=========================================================="
                    print "Device:" + result
                    print "Closeness measure:" + str(closeness)

    elif type == 2:
        minSlope = threshold
        results = {}
        DataBase = AddToDB.getDB()
        for key in DataBase.keys():
            if DataBase[key][1] == 2:
                closeness = abs(test[0] - DataBase[key][0][0])
                results[key] = closeness
                if closeness < minSlope:
                    minSlope = closeness
                    result = key
                    resultSig = DataBase[key]
        sorted_results = sorted(results.iteritems(), key=operator.itemgetter(1))
        for x in sorted_results:
            print"=========================================================="
            print "Device:  " + str(x[0])
            print "Closeness value: " + str(x[1])
    elif type == 3:
        minSlope = threshold
        results = {}
        DataBase = AddToDB.getDB()
        for key in DataBase.keys():
            if DataBase[key][1] == 3:
                closeness = abs(test[0] - DataBase[key][0][0])
                results[key] = closeness
                if closeness < minSlope:
                    minSlope = closeness
                    result = key
                    resultSig = DataBase[key]
        sorted_results = sorted(results.iteritems(), key=operator.itemgetter(1))
        for x in sorted_results:
            print"=========================================================="
            print "Device:  " + str(x[0])
            print "Closeness value: " + str(x[1])
    elif type == 4:
        minSlope = threshold
        results = {}
        DataBase = AddToDB.getDB()
        for key in DataBase.keys():
            if DataBase[key][1] == 4:
                print test[0]
                print DataBase[key][0][0]
                closeness = abs(test[0] - DataBase[key][0][0])
                results[key] = closeness

                if closeness < minSlope:
                    minSlope = closeness
                    result = key
                    resultSig = DataBase[key]
        sorted_results = sorted(results.iteritems(), key=operator.itemgetter(1))
        for x in sorted_results:
            print"=========================================================="
            print "Device:  " + str(x[0])
            print "Closeness value: " + str(x[1])

    else:
        print "Invalid Type"
        sys.exit(0)
    print "++++++++++++++++++++++++++++++++++++++++++++++++++"
    print "CLOSEST MATCHING DEVICE:" + str(result)
    print "++++++++++++++++++++++++++++++++++++++++++++++++++"
    return result
