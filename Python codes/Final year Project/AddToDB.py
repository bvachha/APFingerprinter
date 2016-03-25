import Type2Utilities
import Type3Utilities

__author__ = 'bakhtyar'

import os
import Type1Utilities
import cPickle


# TODO Add some sort of authentication mechanism to prevent unauthorized additions to the Database
def add2Db(name, sig, type):
    """
    Add the signature to the database
    :param name: ID of the device
    :param sig: Signature record
    :param type: 1-Device driver fingerprint,2-Beacon fingerprint,3-Active clockskew fingerprint
    :return: returns nothing
    """
    pathDB = "MasterSigBase/SigBase.pkl"
    Db = open(pathDB, 'r')
    temp = {}
    try:
        temp = cPickle.load(Db)
    except(EOFError):
        Db.close()
        temp = {}
        temp[name] = (sig, type)  # creating the final entry to be added
        print "[+] Signature added successfully"
        Db = open(pathDB, 'w')
        cPickle.dump(temp, Db, -2)
        print "[+] Database updated"
        Db.close()
        return
    Db.close()
    if name not in temp.keys():
        temp[name] = (sig, type)  # creating the final entry to be added
        print "[+] Signature added successfully"
        Db = open(pathDB, 'w')
        cPickle.dump(temp, Db, -2)
        print "[+] Database updated"
    else:
        print "[-] Entry for this device already exists"
    Db.close()


def getDB():
    """
    Return the data from the database
    :return: a list of active database records
    """
    pathDB = "MasterSigBase/SigBase.pkl"
    Db = open(pathDB, 'r')
    temp = {}
    temp = cPickle.load(Db)
    Db.close()
    return temp


def removeFromDB(KeyValue):
    """
     Remove specified Key value from Database
    :param KeyValue: ID of entry to remove
    :return: Returns nothing
    """
    pathDB = "MasterSigBase/SigBase.pkl"
    Db = open(pathDB, 'r')
    temp = {}
    temp = cPickle.load(Db)
    Db.close()
    if KeyValue in temp.keys():
        temp.pop(KeyValue)
        print "Successfully removed entry: " + KeyValue
    else:
        print "Key value not present"
        return
    Db = open(pathDB, 'w')
    cPickle.dump(temp, Db, -2)
    print "Database updated"
    Db.close()
    print "Database closed"


def printDBkeys():
    """
    Function to print a list of all the signature IDs in database
    :return: Returns nothing
    """
    pathDB = "MasterSigBase/SigBase.pkl"
    Db = open(pathDB, 'r')
    temp = {}
    temp = cPickle.load(Db)
    Db.close()
    print" Current Database:"
    print "--------------------------------------------------------------"
    print "|\tDevice\t\t|\tType\t|"
    print "--------------------------------------------------------------"

    for x in temp.keys():
        print "|\t" + str(x) + "\t|\t" + str(temp[x][1]) + "\t|"
        print "--------------------------------------------------------------"


def printDBval(keyVal):
    """
    Function to print the signature of a device in database
    :return: Returns nothing
    """
    pathDB = "MasterSigBase/SigBase.pkl"
    Db = open(pathDB, 'r')
    temp = {}
    temp = cPickle.load(Db)
    Db.close()
    if keyVal in temp.keys():
        print "Device: "+str(keyVal)+"\nSignature"+str(temp[keyVal])
    else:
        print "Signature ID not present in Database"


def purgeDB():
    """
    Remove all key values from Database
    :return: Returns nothing
    """
    print "ARE YOU SURE YOU WANT TO PURGE THE DATABASE?(yes/no)"
    answer = raw_input(">")
    if answer == "yes":
        pathDB = "MasterSigBase/SigBase.pkl"
        temp = {}
        Db = open(pathDB, 'w')
        cPickle.dump(temp, Db, -2)
        print "Database purged"
        Db.close()
        print "Database closed"
    else:
        return


def addAll(path, type, lim=0):
    if type == 1:
        folder = os.listdir(path)
        for name in folder:
            if name[-4:] == 'pcap':
                sig, status = Type1Utilities.Generator(path + str(name), lim)
                add2Db(name[:-5], sig, 1)
        printDBkeys()
    elif type == 2:
        folder = os.listdir(path)
        for name in folder:
            if name[-4:] == 'pcap':
                print "Processing " + str(path + str(name))
                sig = Type2Utilities.create_Type2_Signature(path + str(name))
                add2Db(name[:-5], sig, 2)
        printDBkeys()
    elif type == 3:
        folder = os.listdir(path)
        for name in folder:
            if name[-4:] == 'pcap':
                sig = Type3Utilities.create_type3_signature(path + str(name), binning=True)
                add2Db(name[:-5], sig, 3)
        printDBkeys()
    elif type == 4:
        folder = os.listdir(path)
        for name in folder:
            if name[-4:] == 'pcap':
                sig = Type3Utilities.create_type4_signature(path + str(name), binning=True)
                add2Db(name[:-5], sig, 4)
        printDBkeys()
    else:
        print "Invalid Type"


def purge_Type(type):
    """
     Remove specified Key type from Database
    :param type: type of entry to remove
    :return: Returns nothing
    """
    pathDB = "MasterSigBase/SigBase.pkl"
    Db = open(pathDB, 'r')
    temp = {}
    temp = cPickle.load(Db)
    Db.close()
    for KeyValue in temp.keys():
        if temp[KeyValue][1] == type:
            temp._delitem_(KeyValue)
        print "Successfully removed entry: " + KeyValue
    Db = open(pathDB, 'w')
    cPickle.dump(temp, Db, -2)
    print "Database updated"
    Db.close()
    print "Database closed"
