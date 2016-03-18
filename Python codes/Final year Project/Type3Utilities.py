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

import binascii
import numpy as np
from decimal import *

import dpkt
import matplotlib.cm as cm
from pylab import figure, show

import Type2Utilities

getcontext().prec = 9  # Set precision of the decimal values to 9


def ByteOrderCheck(dumppath):
    """
    Function to check the byte order of the packet.
    :param dumppath: Path of the dumpfile
    :return: True if Network Byte order else false
    """
    count = 0
    f = open(dumppath)  # Open pcap file
    pc = dpkt.pcap.Reader(f)  # Read data from the file into pc
    testarr = []
    for ts, rawdata in pc:
        if count > 5:
            break
        tap = dpkt.ethernet.Ethernet(rawdata)  # Format as a Ethernet packet
        ipdata = tap.data  # Extract Ip Data
        icmpdata = ipdata.data  # Extract ICMP data
        testarr.append(int(binascii.hexlify(icmpdata.data[-4:]), 16))
        count += 1
    for x in xrange(4):
        if abs(testarr[x] - testarr[x + 1]) > 4000:
            return True
    return False


def ICMPSkewGenerator(dumppath, binning=True, binsize=10):
    """
    Creates a skew list for pcap file containing ICMP timestamp data
    :param dumppath: Path for the dump file
    :param binning: Do we want binning for this signature?
    :param binsize: size of the bin in the signature
    :return: List of coordinates for the ICMP Skew
    """
    # Todo set a flag or a test to verify the ordering of the timestamp :DONE
    reversal = ByteOrderCheck(dumppath)
    print ("Creating skew list for file: " + dumppath)
    sysclkinit = ''  # Initial system clock value
    rclkinit = ''  # Initial remote clock value
    skew = []  # List of skews
    f = open(dumppath)  # Open pcap file
    pc = dpkt.pcap.Reader(f)  # Read data from the file into pc

    for ts, rawdata in pc:
        tap = dpkt.ethernet.Ethernet(rawdata)  # Format as a Ethernet packet
        ipdata = tap.data  # Extract Ip Data
        icmpdata = ipdata.data  # Extract ICMP data

        if reversal == True:  # Timestamp follows Network Byte Order

            if rclkinit == '':  # Set initial values
                sysclkinit = int(binascii.hexlify(icmpdata.data[-12:-8]), 16)  # Set initial Sender timestamp
                rclkinit = []

                for i in xrange(len(icmpdata.data) - 4, len(icmpdata.data)):
                    rclkinit.append(binascii.hexlify(icmpdata.data[i]))

                rclkinit = "".join(reversed(rclkinit))
                rclkinit = int(rclkinit, 16)
                sclk = sysclkinit
                rclk = rclkinit

            else:
                sclk = int(binascii.hexlify(icmpdata.data[-12:-8]), 16)
                rclk = [binascii.hexlify(icmpdata.data[i]) for i in xrange(len(icmpdata.data) - 4, len(icmpdata.data))]
                rclk = "".join(reversed(rclk))
                rclk = int(rclk, 16)

            RTval = rclk - rclkinit  # Extract Remote clock values
            STval = sclk - sysclkinit  # Extract system clock values
            skew.append((STval, RTval - STval))
        else:
            if rclkinit == '':  # Set initial values
                sysclkinit = int(binascii.hexlify(icmpdata.data[-12:-8]), 16)
                rclkinit = int(binascii.hexlify(icmpdata.data[-4:]), 16)
                sclk = sysclkinit
                rclk = rclkinit
            else:
                sclk = int(binascii.hexlify(icmpdata.data[-12:-8]), 16)
                rclk = int(binascii.hexlify(icmpdata.data[-4:]), 16)

            RTval = rclk - rclkinit  # Extract Remote clock values
            STval = sclk - sysclkinit  # Extract system clock values
            skew.append((STval, RTval - STval))

    if binning:
        newskew = binner(skew, binsize)
        return newskew
    return skew


def TCPSkewGenerator(dumppath, binning=True, binsize=10, SIncr=100):
    """
    Creates a skew list for pcap file containing TCP timestamp data
    :param dumppath: Path for the dump file
    :param binning: Do we want to use binning for the signature
    :param binsize: size of the bin for the signature
    :param SIncr: increments for the system clock
    :return: returns the coordinate list for the skew
    """
    # ToDo system timestamps will be increments of 1000 and remote timestamps are extracted as last but 4 bytes of the received packet:DONE

    print ("Creating skew list for file: " + dumppath)
    sysclkinit = ''  # Initial system clock value
    rclkinit = ''  # Initial remote clock value
    STval = 0
    skew = []  # List of skews
    f = open(dumppath)  # Open pcap file
    pc = dpkt.pcap.Reader(f)  # Read data from the file into pc
    for ts, rawdata in pc:
        tap = dpkt.ethernet.Ethernet(rawdata)  # Format as a Ethernet packet
        ipdata = tap.data  # Extract Ip Data
        tcpdata = str(ipdata.data)  # Extract TCP data
        if rclkinit == '':  # Set initial values
            rclkinit = int(binascii.hexlify(tcpdata[-8:-4]), 16)
            sclk = 0
            rclk = rclkinit
        else:
            rclk = int(binascii.hexlify(tcpdata[-8:-4]), 16)

        RTval = rclk - rclkinit  # Extract Remote clock values
        STval = STval + SIncr  # Extract system clock values
        skew.append((STval, RTval - STval))

    if binning:
        newskew = binner(skew, binsize)
        return newskew
    return skew


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
    ax1.set_ylim(0, max(yvals) + 5)
    ax1.set_ylabel('Skew')
    ax1.set_xlabel('Time')
    ax1.legend()
    for label in ax1.get_xticklabels():
        label.set_color('r')
    show()


def create_type3_signature(path, binning=True, binsize=10, Sincr=100):
    skew = ICMPSkewGenerator(path, binning, binsize)
    xvals = []
    yvals = []
    print "xxxxxxxxxxxxxxx"
    for j in xrange(len(skew)):
        xvals.append(
            float(skew[j][0] - skew[0][0]))  # List of X coordinates as the centered timestamp values of fingerprinter
        yvals.append(
            float(skew[j][1] - skew[0][1]))  # List of  Y coordinates as the difference values of the device timestamps
    slope, intercept = np.polyfit(xvals, yvals, 1)
    return slope, intercept


def create_type4_signature(path, binning=True, binsize=10, Sincr=100):
    skew = TCPSkewGenerator(path, binning, binsize, Sincr)
    xvals = []
    yvals = []
    print "xxxxxxxxxxxxxxx"
    for j in xrange(len(skew)):
        xvals.append(
            float(skew[j][0] - skew[0][0]))  # List of X coordinates as the centered timestamp values of fingerprinter
        yvals.append(
            float(skew[j][1] - skew[0][1]))  # List of  Y coordinates as the difference values of the device timestamps
    slope, intercept = np.polyfit(xvals, yvals, 1)
    return slope, intercept


def main():
    """
    test different functions of this module here
    :return: nothing
    """
    skew = []
    # skew = ICMPLauncher.ICMPlaunch(['192.168.28.25'])
    ByteOrderCheck(
        "/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand1-icmp.pcap")
    ByteOrderCheck(
        "/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/3c77e68d0805.pcap")
    skew.append(ICMPSkewGenerator(
        "/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand2-test.pcap"))
    skew.append(ICMPSkewGenerator(
        "/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand4-icmp.pcap"))
    skew.append(ICMPSkewGenerator(
        "/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/Rand6-icmp.pcap"))
    skew.append(ICMPSkewGenerator(
        "/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/3c77e68d0805.pcap"))
    skew.append(ICMPSkewGenerator(
        "/home/bakhtyar/Dropbox/Mtech Final year project/Python codes/Final year Project/TestDumps/Type3/0c60763ea14e.pcap"))
    Type2Utilities.drawSkewGraph(skew)


if __name__ == '__main__':
    main()

    # ToDO Some of the skews are spreading out due to network order of timestamps :DONE
