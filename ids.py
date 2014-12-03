#!/usr/bin/env python

import socket
from collections import deque
import dpkt

# --------------------------- AUX functions -------------------------------------
def formatIP(ip):
    try:
        return socket.inet_ntop(socket.AF_INET, ip)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, ip)


def formatMac(mac):
    return ':'.join(x.encode('hex') for x in mac)






# --------------------------- ARP Spoofing detector functions -------------------------------------

def ARPSpoofingDetector(packetARP, packetNumber):
    #List with the the relationship between mac and ip address
    macToIP = {
        '\xC0\xA8\x00\x64': '\x7C\xD1\xC3\x94\x9E\xB8',  # 192.168.0.100 | 7c:d1:c3:94:9e:b8
        '\xC0\xA8\x00\x67': '\xD8\x96\x95\x01\xA5\xC9',  # 192.168.0.103 | d8:96:95:01:a5:c9
        '\xC0\xA8\x00\x01': '\xF8\x1A\x67\xCD\x57\x6E'   #  192.168.0.1   | 8:1a:67:cd:57:6e
    }

    if packetARP.spa in macToIP.keys() and packetARP.sha != macToIP[packetARP.spa]:
        print "ARP spoofing attempt! Malicious packet number:{} offending Mac Address:{}".format(packetNumber, formatMac(packetARP.sha))


# --------------------------- port Scan detection functions -------------------------------------

#List with all target systems, in which each target system
portScan = {}
synFlood = {}

def portScanTCP(packetIP, packetNumber):
    packetTCP = packetIP.data
    if packetTCP.flags == dpkt.tcp.TH_SYN:
        portScanGeneral(packetTCP.dport,packetIP, packetNumber)


def portScanGeneral(port, packetIP, packetNumber):
    source = {}
    #Dest not in the array yet.
    if packetIP.dst not in portScan:
        source[packetIP.src] = [{'src': packetIP.src, 'dst': packetIP.dst,'port':port, 'packetNumber': [packetNumber]}]
        portScan[packetIP.dst] = source
    else:
        #Source not in the array from it dest yet.
        if packetIP.src not in portScan[packetIP.dst]:
            source[packetIP.src] = [{'src': packetIP.src, 'dst': packetIP.dst,'port':port, 'packetNumber': [packetNumber]}]
            portScan[packetIP.dst] = source
        #both source and Dest array exists
        else:
            arrayOfPort = portScan[packetIP.dst][packetIP.src]
            for value in arrayOfPort:
                #if port already there, add the packet number to the packetNumberArray
                if port == value['port']:
                    value['packetNumber'].append(packetNumber)
                    return
                #if port already  is not there, create the list with the packet number on it
            portScan[packetIP.dst][packetIP.src].append({'src': packetIP.src, 'dst': packetIP.dst,'port':port, 'packetNumber': [packetNumber]})


def countingPortScans():
        for dest in portScan:
            source = portScan[dest]

            for src in source:
                arrayOfPort = source[src];
                packetsNumberArray = []
                for value in arrayOfPort:
                    packetsNumberArray += value['packetNumber']
                if (len(arrayOfPort) > 100):
                    print "\n"
                    print "Port scan attempt! source address: {} | victim address:{} | Offending packets: {}" \
                          "".format(formatIP(arrayOfPort[0]['src']), formatIP(arrayOfPort[0]['dst']), packetsNumberArray)



# --------------------------- synFlood detection functions -------------------------------------
def synFloodDetector(packetIP, ts, packetNumber):
        arrayOfPacketNumber = []
        tcpPacket = packetIP.data
        #check if packet is a SYN packet
        if tcpPacket.flags == dpkt.tcp.TH_SYN:
            if packetIP.dst in synFlood:
                arrayOfValues = synFlood[packetIP.dst]
                while len(arrayOfValues) > 0:
                    value = arrayOfValues[0]
                    if ts - value['ts'] >= 1:
                        arrayOfValues.popleft()
                    else:
                        break

                arrayOfValues.append({'src': packetIP.src, 'dst': packetIP.dst, 'packetNumber':packetNumber,'ts': ts})

                if len(arrayOfValues) > 100:
                    for value in arrayOfValues:
                        arrayOfPacketNumber.append(value['packetNumber'])

                    print "TCP SYN attempt! source address: {} | victim address: {} | Offending packets: " \
                          "{}".format(formatIP(arrayOfValues[0]['src']),formatIP(arrayOfValues[0]['dst']),arrayOfPacketNumber)
                    print "\n"
                    arrayOfValues.clear()
            else:
                synFlood[packetIP.dst] = deque([{'src': packetIP.src, 'dst':  packetIP.dst, 'packetNumber': packetNumber, 'ts': ts}])

#------------------- main Script -----------------------------
fileString = raw_input("Enter the pcap file (e.g.traces/portscan.pcap):")
f = open(fileString)
pcap = dpkt.pcap.Reader(f)
packetNumber = 0
for ts, buf in pcap:
    packetNumber += 1
    eth = dpkt.ethernet.Ethernet(buf)
    protocol1 = type(eth.data)
    protocol2 = type(eth.data.data)


    if protocol1 is dpkt.arp.ARP:
        ARPSpoofingDetector(eth.data, packetNumber)
    elif protocol2 is dpkt.tcp.TCP:
        portScanTCP(eth.data,packetNumber)
        synFloodDetector(eth.data, ts, packetNumber)
    elif protocol2 is dpkt.udp.UDP:
        portScanGeneral(eth.data.data.dport,eth.data,packetNumber)

countingPortScans()






