__author__ = 'bakhtyar'
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
        temp[name] = (type, sig)  # creating the final entry to be added
        print "[+] Signature added successfully"
        Db = open(pathDB, 'w')
        cPickle.dump(temp, Db, -2)
        print "[+] Database updated"
        Db.close()
        return
    Db.close()
    if name not in temp.keys():
        temp[name] = (type, sig)  # creating the final entry to be added
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
    for x in temp.keys():
        print "Device:" + str(x)


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
    pathDB = "MasterSigBase/SigBase.pkl"
    temp = {}
    Db = open(pathDB, 'w')
    cPickle.dump(temp, Db, -2)
    print "Database purged"
    Db.close()
    print "Database closed"