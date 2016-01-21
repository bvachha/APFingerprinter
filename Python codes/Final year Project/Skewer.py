__author__ = 'bakhtyar'
from scapy.all import *
import dpkt
from decimal import *
from scapy.layers.dot11 import *
import binascii
import numpy as np
from pylab import figure, show
import time

interval = 0.102400
apClock = [0.000000]
sysClock = [0.000000]
sysclkinit = 0	# Initial system clock value
apclkinit = 0	# Initial AP clock value
skew = []

getcontext().prec = 6 #Set precision of the decimal values to 9


def beaconsignature(path):
    xvals = []
    yvals = []
    print ("Creating skew list for file: "+path)
    sysclkinit = 0	# Initial system clock value
    apclkinit = 0	# Initial AP clock value
    status = False
    count = 0
    skew = []	# List of skews
    f = open(path) #Open pcap file
    pc = dpkt.pcap.Reader(f)	#Read data from the file into pc
    dl=pc.datalink()
    if pc.datalink() == 127: #Check if RadioTap
        for ts, rawdata in pc:
            tap = dpkt.radiotap.Radiotap(rawdata)	#Format as a Radiotap packet
            t_len=binascii.hexlify(rawdata[2:3])    #Extract the length of the radiotap data, including the radiotap header.
            t_len=int(t_len,16)	#Convert to hexadecimal
            wlan = dpkt.ieee80211.IEEE80211(rawdata[t_len:])
            if wlan.type == 0 and wlan.subtype == 8: # Indicates a beacon frame
                count += 1
                time = binascii.hexlify(rawdata[t_len+24:t_len+32]) # Get hex value of the timestamp bytes
                time = "".join(reversed([time[i:i+2] for i in range(0, len(time), 2)]))	# Convert network byte order to the regular
                time = int(time,16)	# Convert from hexadecimal to integer
                if apclkinit == 0:
                    sysclkinit = Decimal(ts)	#Set initial value of the system clock
                    apclkinit = Decimal(time)	#Set initial value of the AP clock
                else:
                    skew.append([Decimal(ts) - Decimal(sysclkinit),(Decimal(time) - Decimal(apclkinit))-(Decimal(ts) - Decimal(sysclkinit))*1000000])

    if count > 1000:    #Atleast 1000 skew values were calculated from given pcap file
        status = True

    for j in xrange(len(skew)):
        xvals.append(float(skew[j][0])-float(skew[0][0]))
        yvals.append(float(skew[j][1])-float(skew[0][1]))

    slope, intercept=np.polyfit(xvals,yvals,1)
    signature=(slope, intercept)
    return signature, status

def skewfilterDpkt(dumppath):	#Uses a dpkt approach to generate skew tuples
	print ("Creating skew list for file: "+dumppath)
	sysclkinit = 0	# Initial system clock value
	apclkinit = 0	# Initial AP clock value
	skew = []	# List of skews
	f = open(dumppath) #Open pcap file
	pc = dpkt.pcap.Reader(f)	#Read data from the file into pc
	dl=pc.datalink()
	if pc.datalink() == 127: #Check if RadioTap
		for ts, rawdata in pc:
			tap = dpkt.radiotap.Radiotap(rawdata)	#Format as a Radiotap packet
			t_len=binascii.hexlify(rawdata[2:3])    #Extract the length of the radiotap data, including the radiotap header.
			t_len=int(t_len,16)	#Convert to hexadecimal
			wlan = dpkt.ieee80211.IEEE80211(rawdata[t_len:])
			if wlan.type == 0 and wlan.subtype == 8: # Indicates a beacon frame
				time = binascii.hexlify(rawdata[t_len+24:t_len+32]) # Get hex value of the timestamp bytes
				time = "".join(reversed([time[i:i+2] for i in range(0, len(time), 2)]))	# Convert network byte order to the regular
				time = int(time,16)	# Convert from hexadecimal to integer
				if apclkinit == 0:
					sysclkinit = Decimal(ts)	#Set initial value of the system clock
					apclkinit = Decimal(time)	#Set initial value of the AP clock
				else:
					skew.append([float(Decimal(ts) -sysclkinit),float((Decimal(time) - apclkinit)-(Decimal(ts) - sysclkinit)*1000000)])
	print("Skew successfully generated")
	print ("Number of packets analysed:"+str(len(skew)))
	return skew #TODO for checking linkage REMOVE LATER


"""def skewfilterScapy(dumppath):	#uses a scapy implementation to generate skew tuples
	print ("Creating skew list for file: "+dumppath)
	skew = []
	dump = sniff(offline=dumppath,count = 100000)  # Store data in dump
	print "Dumpfile Created Succesfully"
	for x in xrange(1,len(dump)):
		sysClock.append((Decimal(dump[x].time) - Decimal(dump[0].time))*1000000)	#add shifted system clock values to list
		apClock.append(Decimal(dump[x].timestamp) - Decimal(dump[0].timestamp))		#add shifted AP clock values to list
		skew.append((Decimal(sysClock[x])/1000000,Decimal(apClock[x])-Decimal(sysClock[x])))	# Generate skew tuples
	print("Skew successfully generated")
	return skew"""


def proc(packet):
    global apclkinit,sysclkinit,skew
    if apclkinit == 0:
        apclkinit = Decimal(packet.timestamp)
        sysclkinit = Decimal(packet.time)
    else:
        skew.append(((Decimal(packet.time) - sysclkinit)*1000000, Decimal(packet.timestamp) - apclkinit))	# Generate skew tuples


def skewfilterScapy(dumppath):	#uses a scapy implementation to generate skew tuples
	sysClockinit = 0
	apClockinit = 0
	print ("Creating skew list for file: "+dumppath)


	sniff(offline=dumppath,count = 100000,prn=proc)  # Store data in dump
	print "Dumpfile Created Succesfully"
	print("Skew successfully generated")
	return skew


def drawSkewGraph(skew): #Accepts a list of skew lists and displays the plots for each
	#TODO accept limits using an optional named parameter

	color = {0:'y',1:'k',2:'b',3:'g',4:'r',5:'c',6:'p'}
	fig = figure(1)
	ax1 = fig.add_subplot(111)
	for i in xrange(len(skew)):
		xvals = []
		yvals = []
		for j in xrange(len(skew[i])):
			xvals.append(float(skew[i][j][0]-skew[i][0][0]))
			yvals.append(float(skew[i][j][1]-skew[i][0][1]))
		slope, intercept = np.polyfit(xvals,yvals,1)
		
		print slope , intercept
		ablineValues = []
		for x in xvals:
			ablineValues.append((slope*x)+intercept)
		ax1.plot(xvals, yvals,str(color[i])+'+')
		ax1.plot(xvals,ablineValues,str(color[i]))
		
		
	ax1.grid(True)
	ax1.set_ylim(0, max(yvals)+5)
	ax1.set_ylabel('Skew')
	ax1.set_xlabel('Time')
	ax1.legend()

	for label in ax1.get_xticklabels():
		label.set_color('r')
	show()
