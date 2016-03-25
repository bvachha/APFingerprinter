__author__ = 'Bakhtyar'
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

import numpy as np

from scapy.layers.dot11 import *


def binner(arr, bins):  # return float values in arr in proper bin
    """
    Places the values from the array in the appropriate bin
    :param arr: Array of timestamp values
    :param bins: List of bin boundaries
    :return: List containing the number of packets in each bin
    """
    a = copy.deepcopy(arr)
    count, ind = 0, 0
    while count < len(a) and ind < len(bins):
        if a[count] < bins[ind]:
            a[count] = bins[ind]
            count += 1
        else:
            ind += 1
    return a


def binavg(arr, bins):  # find the average value of each bin
    """
    Function to find the average value for each bin
    :param arr: Array of timestamp values
    :param bins: List of bin boundaries
    :return: List containing the average of timestamp values in each bin
    """
    a = copy.deepcopy(arr)
    means = []
    count, ind, tmp, binCount = 0, 0, 0.0, 1
    while count < len(a) and ind < len(bins):
        if bins[ind - 1] <= a[count] < bins[ind]:
            tmp = tmp + a[count]
            count += 1
            binCount += 1
        else:
            ind += 1
            means.append(tmp / binCount)
            tmp = 0.0
            binCount = 1
    return means


def binPerc(binnedArray, bins):  # Find percentage of packets in each bin
    """
    Function to calculate the percentage of total packets in each bin
    :param binnedArray: Array of packets sorted into bins
    :param bins: Bin boundary values
    :return: List containing percentage of packets in each bin interval
    """
    a = copy.deepcopy(binnedArray)
    perc = []
    total = len(binnedArray)
    count, ind = 0, 0
    while ind < len(bins):
        tmp = float(a.count(bins[ind]) * 100.0 / float(total))
        perc.append(tmp)
        ind += 1
    return perc


def sigGen(bins, percentages, means):
    signature = []
    for x in xrange(0, min(len(bins), len(percentages), len(means))):  # For each bin, create the tuples
        row = [bins[x], percentages[x], means[x]]
        signature.append(row)
    return signature


def create_type1_signature(path, lim=400):
    status = True
    dump = sniff(offline=path, filter="type mgt subtype probe-resp")
    if dump is None:
        return [], False
    timestamps = []  # List of full resolution timestamps values
    mean = []
    signature = [[]]
    print "Centering Timestamps"
    for x in xrange(0, len(dump)):
        if float(dump[x].time - dump[0].time) < lim + 1:
            timestamps.append(float(dump[x].time - dump[0].time))  # Initialise time-stamps after centering to zero
    '''if timestamps[-1] <= 400.0:
        print "The capture file has less than 400 seconds of data. Signature generation failed"
        return 0'''
    bins = []
    for x in np.arange(0, lim, 1):
        bins.append(x)

    print "Binning timestamps"
    binnedStamps = binner(timestamps, bins)  # Put timestamps in correct bins
    print "Finding Mean values of bins"
    means = binavg(timestamps, bins)  # Find mean of each bin value
    print "Finding percentage distribution of Timestamps"
    percentageBins = binPerc(binnedStamps, bins)  # Find % of total packets in each bin
    signature = sigGen(bins, percentageBins, means)
    print "Signature successfully created"
    return signature, status
