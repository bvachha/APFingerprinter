__author__ = 'bakhtyar'
from pylab import figure, show
from numpy import arange, sin, pi


def DrawSig1(signature):
    xvals = []
    yvals = []
    for i in xrange(len(signature)):
        xvals.append(float(signature[i][0]))
        yvals.append(float(signature[i][1]))
    fig = figure(1)

    ax1 = fig.add_subplot(111)
    ax1.plot(xvals, yvals,'+')
    ax1.grid(True)
    ax1.set_ylim(0, max(yvals)+50)
    ax1.set_ylabel('Time')
    ax1.legend()

    for label in ax1.get_xticklabels():
        label.set_color('r')
    show()

def DrawSig(signature1,signature2):
    x1vals = []
    y1vals = []
    for i in xrange(len(signature1)):
        x1vals.append(signature1[i][0])
        y1vals.append(signature1[i][1])
    x2vals = []
    y2vals = []
    for i in xrange(len(signature2)):
        x2vals.append(signature2[i][0])
        y2vals.append(signature2[i][1])


    fig = figure(1)

    ax1 = fig.add_subplot(221)
    ax2 = fig.add_subplot(223)
    ax1.plot(x1vals, y1vals,'-b', label="Test")
    ax2.plot(x2vals, y2vals,'-r', label= "Match")
    ax1.grid(True)
    ax1.set_ylim(0, max(y1vals)+5)
    ax1.set_ylabel('No. of packets')
    ax1.set_xlabel('Time')
    ax1.set_title('Test')
    ax2.grid(True)
    ax2.set_ylim(0, max(y2vals)+5)
    ax2.set_ylabel('No. of packets')
    ax2.set_xlabel('Time')
    ax2.set_title('Signature')

    ax3 = fig.add_subplot(222)
    ax3.plot(x1vals, y1vals,'-b', label="Test")
    ax3.plot(x2vals, y2vals,'-r', label= "Match")
    ax3.grid(True)
    ax3.set_ylim(0, max(y1vals)+5)
    ax3.set_ylabel('No. of packets')
    ax3.set_xlabel('Time')
    ax3.set_title('Overlap')
    show()

