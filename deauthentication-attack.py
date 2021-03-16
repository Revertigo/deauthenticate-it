import sys
import os
from threading import Thread
import pandas
import time
from scapy.all import *

time_to_sniff = 20

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
        if packet[Dot11].addr1 == temp:
            print("********** new packet **********")
            print (packet[Dot11].addr2)
         
if __name__ == "__main__":
    # interface = sys.argv[1]
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

