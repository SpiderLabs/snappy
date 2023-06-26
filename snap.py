#!/usr/bin/python3

# snap.py v1.0 - trustwave spiderlabs
# (Snap)shot SHA256 hashes of wireless access points to determine whether something
# has changed since your last visit (e.g. rogue AP), plus detect airbase-ng in use.
#
# Feed it .pcap/.cap file for offline mode or change 'sniff' to an interface to run live.
# e.g. ./snap.py goodness.cap

from scapy.layers.dot11 import *
from scapy.sendrecv import sniff
import chardet
import hashlib
import sys

def parse(frame):
    if frame.haslayer(Dot11) and frame.type==0 and frame.subtype==8:
        print("BSSID:", frame.addr3)
        print("SSID:", (frame.info).decode('utf-8'))
        channel=int(ord(frame[Dot11Elt:3].info))
        print("Channel:", channel)
        if frame.haslayer(Dot11EltCountry):
           country=(frame[Dot11EltCountry].country_string).decode('utf-8')
        else:
           country=0
        print("Country:", country)
        print("Supported Rates:", frame.rates)
        erates=frame[Dot11EltRates].info
        print("Extended Rates:", erates)
        if frame.haslayer(Dot11EltCountryConstraintTriplet):
           power=frame[Dot11EltCountryConstraintTriplet].mtp
        else:
           power=0
        print("Max Transmit Power:", power)
        if frame.haslayer(Dot11Beacon):
           cap=frame[Dot11Beacon].cap
        else:
           cap=0
        print("Capabilities:", cap)
        if frame.haslayer(Dot11EltHTCapabilities):
           htmax=frame[Dot11EltHTCapabilities].Max_A_MSDU
           ht=frame[Dot11EltHTCapabilities].summary
        else:
           htmax=0
           ht=0
        print("Max_A_MSDU:", htmax)
        if frame.haslayer(Dot11EltVendorSpecific):
              try:
                  vendor=frame[Dot11EltVendorSpecific:2].oui
              except:
                  vendor=0
        else:
           vendor=0
        print("Vendor:", vendor)
        all=frame.addr3+str(frame.info)+str(channel)+str(country)+str(vendor)+str(frame.rates)+str(erates)+str(power)+str(cap)+str(htmax)+str(vendor)
        print("SHA256: "+(hashlib.sha256(all.encode('utf-8')).hexdigest()))
        airbasesig=str(country)+str(frame.rates)+str(erates)+str(power)+str(cap)+str(htmax)+str(vendor)
#       print("airbase sig: "+(hashlib.sha256(airbasesig.encode('utf-8')).hexdigest()))
        if hashlib.sha256(airbasesig.encode('utf-8')).hexdigest()=="4c847490293ea0bf0cf2fe7ddb02703368aaf8e97ffb16455f0365a7497e2de2":
           print("******** AIRBASE-NG DETECTED AT THIS ACCESS POINT ********\n")
        else:
           print("")

file=sys.argv[1]
sniff(offline=file, prn=parse)
