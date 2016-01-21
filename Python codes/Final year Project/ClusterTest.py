
# needed imports
from sklearn.preprocessing import StandardScaler

from matplotlib import pyplot as plt
from hcluster import pdist,linkage,dendrogram,average,fcluster
import numpy as np
from sklearn.cluster import DBSCAN

from matplotlib.pyplot import scatter
from pylab import figure, show


def dendrogramMaker(X,max_d):
    fig = figure(1)
    plt.figure(figsize=(18, 11))
    ax1 = fig.add_subplot(111)
    X1=[]
    Y1=[]
    Y = pdist(X)
    print Y
    Z = linkage(Y)
    print Z
    clusters = fcluster(Z, max_d, criterion='distance')
    for i in xrange(len(X)):
        X1.append(X[i][0])
        Y1.append(X[i][1])
    ax1.scatter(X1, Y1,
    c=clusters
    #cmap='prism'
    )
    fancy_dendrogram(
        Z,
        truncate_mode='lastp',  # show only the last p merged clusters
        p=5,  # show only the last p merged clusters
        show_leaf_counts=True,  # otherwise numbers in brackets are counts
        leaf_rotation=45.,
        leaf_font_size=12.,
        show_contracted=True,  # to get a distribution impression in truncated branches
    )
    plt.show()

def DBCluster(X,threshold):
    X = StandardScaler().fit_transform(X)
    xx, yy = zip(*X)
    scatter(xx,yy)
    show()
    db = DBSCAN(eps=threshold, min_samples=10).fit(X)
    core_samples = db.core_sample_indices_
    labels = db.labels_
    n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
    print n_clusters_

def teststuff():
    X = np.random.rand(110, 100)
    X[0:100, :] *= 2
    #Y = pdist(X)

    #print Y
    #Z = linkage(Y)
    #print Z

    plt.figure(figsize=(15, 10))
    plt.title('Hierarchical Clustering Dendrogram')
    plt.xlabel('sample index')
    plt.ylabel('distance')
    #dendrogram(
    #    Z,
    #    leaf_rotation=90.,  # rotates the x axis labels
    #    leaf_font_size=8.,  # font size for the x axis labels
    #)
    plt.scatter(X[:][0], X[:][1], cmap='prism')
    plt.show()
    print 'done'


def fancy_dendrogram(*args, **kwargs):
    max_d = kwargs.pop('max_d', None)
    if max_d and 'color_threshold' not in kwargs:
        kwargs['color_threshold'] = max_d
    annotate_above = kwargs.pop('annotate_above', 0)

    ddata = dendrogram(*args, **kwargs)

    if not kwargs.get('no_plot', False):
        plt.title('Hierarchical Clustering Dendrogram (truncated)')
        plt.xlabel('sample index or (cluster size)')
        plt.ylabel('distance')
        for i, d, c in zip(ddata['icoord'], ddata['dcoord'], ddata['color_list']):
            x = 0.5 * sum(i[1:3])
            y = d[1]
            if y > annotate_above:
                plt.plot(x, y, 'o', c=c)
                plt.annotate("%.3g" % y, (x, y), xytext=(0, -5),
                             textcoords='offset points',
                             va='top', ha='center')
        if max_d:
            plt.axhline(y=max_d, c='k')
    return ddata