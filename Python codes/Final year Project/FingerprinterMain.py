from scapy.all import *
from scapy.layers.inet import *
import DriverFingerprint
import AddToDB
import Skewer

__author__ = "Bakhtyar"


# Todo graph menu
# Todo Database Management menu


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

        if option == 1:     #Test if the host is accessible using ICMP or TCP
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

        elif option == 2:
            # TODO Fingerprint addition menu
            sigtype = 0

            while sigtype != 4:
                print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" \
                      "\nEnter the type of signature" \
                      "\n1)Device Driver" \
                      "\n2)Clock skew(AP)" \
                      "\n3)Clock skew(Multihop)" \
                      "\n4)Back"
                sigtype = input(">")

                if sigtype == 1:
                    # TODO Driver fingerprint input
                    print("Enter the path of the pcap file containing the probe request frames")
                    path = raw_input(">")
                    print "Enter the device ID"
                    deviceid = raw_input(">")
                    driversignature, status = DriverFingerprint.Generator(path)
                    if status:
                        print "Signature has been created"
                        AddToDB.add2Db(deviceid, driversignature, 1)
                        print "Signature successfully added to database"
                    else:
                        print "Error in signature pcap file"

                elif sigtype == 2:
                    # TODO AP fingerprint input
                    print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" \
                          "\nEnter the path of the pcap file containing the beacon frames"
                    path = raw_input(">")
                    print "Enter the device ID"
                    id = raw_input(">")
                    driversignature, status=Skewer.beaconsignature(path)
                    if status:
                        print "Signature has been created"
                        AddToDB.add2Db(id, driversignature, 2)
                        print "Signature successfully added to database"
                    else:
                        print "Error in signature pcap file"



                elif sigtype == 3:
                    # Todo Multihop clockskew signature input
                    pass

                elif sigtype == 4:
                    break

                else:
                    print "Please choose a valid option"

        elif option == 3:
            # TODO Fingerprint analysis and matching menu
            pass

        elif option == 4:
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

                elif choice==2:
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

        elif option == 5:
            exit()

        else:
            print "Incorrect option passed"


if __name__ == '__main__':
    main()
