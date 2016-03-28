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

# TODO return signatures instead of lists of coordinates

import binascii
import numpy as np
from decimal import *

import dpkt
import matplotlib.cm as cm
from pylab import figure, show
from scapy.layers.dot11 import *

interval = 0.102400
apClock = [0.000000]
sysClock = [0.000000]
sysclkinit = 0  # Initial system clock value
apclkinit = 0  # Initial AP clock value
skew = []

getcontext().prec = 9  # Set precision of the decimal values to 9


def binner(skew, binsize):
    """
    puts the timestamps in the bin and generates the average timestamp for all the devices in the bin
    :param skew: timestamp list to be binned
    :param binsize: size of the bin
    :return: list of the binned values
    """
    newskew = []
    for x in xrange(0, len(skew), binsize):
        temp = []
        count = 0
        for y in xrange(binsize):
            if x + y > len(skew) - 1:
                break
            temp.append(skew[x + y][1])
            count += 1
        newskew.append([skew[x][0], sum(temp) / count])
    return newskew


def skew_generator_DPKT(dumppath, binning=True, binsize=10, size=0):
    """
    Uses a dpkt approach to generate skew tuples
    :param dumppath: path of the pcap file to process
    :param binning: Do we use binning for the signature
    :param binsize: size of the bin to generate the signature
    :return: updated skew list
    """
    print ("Creating skew list for file: " + dumppath)
    counter = 0
    sysclkinit = 0  # Initial system clock value
    apclkinit = 0  # Initial AP clock value
    skew = []  # List of skews
    f = open(dumppath)  # Open pcap file
    pc = dpkt.pcap.Reader(f)  # Read data from the file into pc
    dl = pc.datalink()
    if pc.datalink() == 127:  # Check if RadioTap
        for ts, rawdata in pc:
            if counter > size:
                break
            tap = dpkt.radiotap.Radiotap(rawdata)  # Format as a Radiotap packet
            t_len = binascii.hexlify(
                rawdata[2:3])  # Extract the length of the radiotap data, including the radiotap header.
            t_len = int(t_len, 16)  # Convert to hexadecimal
            wlan = dpkt.ieee80211.IEEE80211(rawdata[t_len:])
            if wlan.type == 0 and wlan.subtype == 8:  # Indicates a beacon frame
                time = binascii.hexlify(rawdata[t_len + 24:t_len + 32])  # Get hex value of the timestamp bytes
                time = "".join(reversed(
                    [time[i:i + 2] for i in range(0, len(time), 2)]))  # Convert network byte order to the regular
                time = int(time, 16)  # Convert from hexadecimal to integer
                if apclkinit == 0:
                    sysclkinit = Decimal(ts)  # Set initial value of the system clock
                    apclkinit = Decimal(time)  # Set initial value of the AP clock
                else:
                    skew.append([float(Decimal(ts) - sysclkinit),
                                 float((Decimal(time) - apclkinit) - (Decimal(ts) - sysclkinit) * 1000000)])
            counter += 1
    print("Skew successfully generated")
    print ("Number of packets analysed:" + str(len(skew)))
    if binning:
        newskew = binner(skew, binsize)
        return newskew
    return skew

def skewfilterScapy(dumppath):  # uses a scapy implementation to generate skew tuples
    print ("Creating skew list for file: " + dumppath)
    skew = []
    dump = sniff(offline=dumppath, count=100000)  # Store data in dump
    print "Dumpfile Created Succesfully"
    for x in xrange(1, len(dump)):
        sysClock.append(
            (Decimal(dump[x].time) - Decimal(dump[0].time)) * 1000000)  # add shifted system clock values to list
        apClock.append(Decimal(dump[x].timestamp) - Decimal(dump[0].timestamp))  # add shifted AP clock values to list
        skew.append(
            (Decimal(sysClock[x]) / 1000000, Decimal(apClock[x]) - Decimal(sysClock[x])))  # Generate skew tuples
    print("Skew successfully generated")
    return skew


def drawSkewGraph(skew, drawcurve=True):
    """
     Accepts a list of skew lists and displays the plots for each
    :param skew: the list of skews to be plotted
    :param drawcurve: plot the best fit line as well?
    :return: nothing
    """
    # TODO accept limits using an optional named parameter
    lens = []
    for x in xrange(len(skew)):
        lens.append(len(skew[x]))
    print lens
    minlen = min(lens)
    print minlen
    color = iter(cm.rainbow(np.linspace(0, 1, len(skew))))  # Dictionary of colour parameters
    fig = figure(1)
    ax1 = fig.add_subplot(111)
    for i in xrange(len(skew)):
        xvals = []
        yvals = []
        for j in xrange(len(skew[i])):
            xvals.append(float(skew[i][j][0] - skew[i][0][
                0]))  # List of X coordinates as the centered timestamp values of fingerprinter
            yvals.append(float(skew[i][j][1] - skew[i][0][
                1]))  # List of  Y coordinates as the difference values of the device timestamps
        slope, intercept = np.polyfit(xvals, yvals, 1)
        if abs(slope) < 0.000001:
            print "Device" + str(i) + ":" + str(slope * 10000) + " " + str(intercept)
        else:
            print "Device" + str(i) + ":" + str(slope) + " " + str(intercept)
        ablineValues = []
        for x in xvals:
            ablineValues.append((slope * x))
        currcol = next(color)
        ax1.scatter(xvals, yvals, color=currcol, marker='+', label="Device" + str(i))
        if drawcurve:
            ax1.plot(xvals, ablineValues, color=currcol)
    ax1.grid(True)
    ax1.set_ylim(min(y1), max(yvals) + 5)
    ax1.set_ylabel('Skew')
    ax1.set_xlabel('Time')
    ax1.legend()
    for label in ax1.get_xticklabels():
        label.set_color('r')
    show()


# Todo argument for size of the signature to test
def create_type2_signature(path, size=3000):
    """
    creates the final signature from the pcap file
    :param path: path to the pcap file containing the signature
    :return: slope and intercept pair for the device
    """
    skew = skew_generator_DPKT(path, size=size)
    xvals = []
    yvals = []
    print "xxxxxxxxxxxxxxxxxxxxxxxxxx"
    for j in xrange(len(skew)):
        xvals.append(
            float(skew[j][0] - skew[0][0]))  # List of X coordinates as the centered timestamp values of fingerprinter
        yvals.append(
            float(skew[j][1] - skew[0][1]))  # List of  Y coordinates as the difference values of the device timestamps
    slope, intercept = np.polyfit(xvals, yvals, 1)
    return slope, intercept
