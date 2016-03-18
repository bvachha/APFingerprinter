from scapy.layers.inet import *

import AddToDB
import Comparator
import Type1Utilities
import Type2Utilities
import Type3Utilities

__author__ = "Bakhtyar"


# Todo graph menu
# Todo Database Management menu:DONE
# ToDo Extract skew from file and ask to store

def ICMPinger(target='192.168.0.1'):
    """
    Uses ICMP ping to determine if the host is active
    :param target: IP address in string format
    :return: Returns true if the Host device responds to the ICMP ping
    """
    print "Running ICMP test on " + target
    result = False
    ans = sr1(IP(dst=target) / ICMP(), timeout=5)
    if ans == None:
        print "Host down or unreachable through ICMP"
        return False
    else:
        ans.summary(lambda (s, r): r.sprintf("%ICMP.type% is alive"))
        return True


def TCPinger(target='192.168.0.1'):
    """
    Uses half open TCP connection to determine if the packet is accessible
    :param target: IP address in string format
    :return: Returns true if the Host device responds to the TCP syn packet
    """
    print "Running TCP test on " + target
    ans = sr1(IP(dst=target) / TCP(dport=80, flags="S"), timeout=5)
    if ans == None:
        print "Host down or unreachable through TCP"
        return False
    else:
        ans.summary(lambda (s, r): r.sprintf("%IP.src% is alive"))
        return True


def live_host_check():
    print "Enter the address"
    target = raw_input(">")
    hostup = False

    if ICMPinger(target):
        print "ICMP check successful => Host is up and responding to ICMP pings"
        hostup = True

    elif TCPinger(target) and hostup == False:
        print "TCP check successful => Host is up and responding to TCP pings"
        hostup = True

    elif not hostup:
        print "Host is down"


def add_New_Signature():
    # TODO Fingerprint addition menu
    sigtype = 0

    while sigtype != 4:
        print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" \
              "\nEnter the type of signature" \
              "\n1)Device Driver" \
              "\n2)Clock skew(AP)" \
              "\n3)Clock skew(Remote device)" \
              "\n4)Back"
        sigtype = input(">")

        if sigtype == 1:
            # TODO Driver fingerprint input
            print("Enter the path of the pcap file containing the probe request frames")
            path = raw_input(">")
            print "Enter the device ID"
            deviceid = raw_input(">")
            driversignature, status = Type1Utilities.Generator(path)
            if status:
                print "Signature has been created"
                AddToDB.add2Db(deviceid, driversignature, 1)
                print "Signature successfully added to database"
            else:
                print "Error in signature pcap file"

        elif sigtype == 2:
            # TODO AP fingerprint input : Done
            print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" \
                  "\nEnter the path of the pcap file containing the beacon frames"
            path = raw_input(">")
            print "Enter the device ID"
            id = raw_input(">")
            driversignature, status = Type2Utilities.create_Type2_Signature(path)
            if driversignature != None:
                print "Signature has been created"
                AddToDB.add2Db(id, driversignature, 2)
                print "Signature successfully added to database"
            else:
                print "Error in signature pcap file"

        elif sigtype == 3:
            # Todo User device clockskew signature input
            print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" \
                  "\nEnter the path of the pcap file containing the beacon frames"
            path = raw_input(">")
            print "Enter the skew type(ICMP:1/TCP:2):"
            signature_Feature = input(">")

            try:
                assert (signature_Feature == 1 or signature_Feature == 2), "Invalid signature type"
            except AssertionError:
                print "Invalid signature type"
                break
            print "Enter the device ID"
            id = raw_input(">")

            if signature_Feature == 1:
                skew = Type3Utilities.ICMPSkewGenerator(path)
                if skew != None:
                    slope, intercept = Type2Utilities.create_Type2_Signature(skew)
                    print "Signature has been created"
                    AddToDB.add2Db(id, (slope, intercept), 3)
                    print "Signature successfully added to database"
            elif signature_Feature == 2:
                skew = Type3Utilities.TCPSkewGenerator(path)
                if skew != None:
                    slope, intercept = Type2Utilities.create_Type2_Signature(skew)
                    print "Signature has been created"
                    AddToDB.add2Db(id, (slope, intercept), 4)
                    print "Signature successfully added to database"

            else:
                print "Error in signature pcap file"

        elif sigtype == 4:
            break

        else:
            print "Please choose a valid option"


def authorization_check():
    # TODO Fingerprint analysis and matching menu
    print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" \
          "\nEnter the path of the pcap file containing the beacon frames"
    path = raw_input(">")
    print "Enter the device type(1:Driver,2:Access Point,3:Remote Device)"
    id = raw_input(">")
    if type == 1:
        pass
    elif type == 2:
        driversignature, status = Type2Utilities.create_Type2_Signature(path)
        result = Comparator.findMatchingSignature(driversignature)
        print result
    elif type == 3:
        testskew = Type3Utilities.ICMPSkewGenerator(path)
        testSig = Type2Utilities.create_Type2_Signature(testskew)
        result = Comparator.findMatchingSignature(testSig, 3)


def db_Manager():
    choice = 0
    while choice != 5:
        print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" \
              "\nEnter the option" \
              "\n1)View the current Database" \
              "\n2)View an entry" \
              "\n3)Delete an entry" \
              "\n4)Purge the database" \
              "\n5)Back"
        choice = input(">")

        if choice == 1:
            AddToDB.printDBkeys()

        elif choice == 2:
            print "Enter the ID to view"
            id = raw_input(">")
            AddToDB.printDBval(id)

        elif choice == 3:
            print "Enter the key value to delete"
            key = raw_input(">")
            AddToDB.removeFromDB(key)

        elif choice == 4:
            print("Are you sure you wish to delete the entire signature file??(Y/n)")
            check = raw_input(">")

            if check == 'Y' or check == 'y':
                AddToDB.purgeDB()

            else:
                pass

        elif choice == 5:
            break

        else:
            print "Invalid option"


def main():
    """
    The main file for the project. Guides the users through the process
    :return: returns nothing
    """
    option = 0
    while option != 5:
        print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" \
              "\nWelcome to the Device Identification System" \
              "\nPlease Enter the activity to perform" \
              "\n1) Live host check" \
              "\n2) Add a new signature" \
              "\n3) Test the authorization of a device" \
              "\n4)Database Management Menu" \
              "\n5)Exit"
        option = input(">")

        if option == 1:  # Test if the host is accessible using ICMP or TCP
            live_host_check()

        elif option == 2:
            add_New_Signature()

        elif option == 3:
            authorization_check()

        elif option == 4:
            db_Manager()

        elif option == 5:
            exit()

        else:
            print "Incorrect option passed"


if __name__ == '__main__':
    main()
