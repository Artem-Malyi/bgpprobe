#!/usr/bin/env python
# -*- coding: utf8 -*-


# BGP message types:
# 1 - OPEN
# 2 - UPDATE
# 3 - NOTIFICATION
# 4 - KEEPALIVE

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


# to run the current script from any location near to scapy/
import os
os.sys.path.append('./scapy')

# for setting iptables to suppress output tcp rst packets
import subprocess 

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.bgp import *

import logging
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO, filename='myapp.log')


class tcpFlags:
    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16
    URG = 32

class bgpState:
    IDLE = 0
    CONNECT = 1
    ACTIVE = 2
    OPENSENT = 3
    OPENCONFIRMED = 4
    ESTABLISHED = 5

class bgpProbe:
    
    def __init__(self, outNic, myIp):
        self.outNic = outNic
        self.myIp = myIp
        self.srcPort = random.randint(40000, 65535)
        self.randomSeq = int(RandInt())
        self.handshakeOk = False
        self.bgpOpenSent = False
        self.firstKeepAliveSent = False
        self.state = bgpState.IDLE
        self.peerIp = "0.0.0.0"
        
        
    def connect(self, peerIp):
        self.peerIp = peerIp
        logging.info("[i] trying to connect to %s", self.peerIp)

        syn = Ether() / IP(dst=self.peerIp, id=int(RandShort())) / TCP(sport=self.srcPort, dport=179, ack=0, seq=self.randomSeq, flags="S")
        logging.info("[i] sending SYN packet: %s", syn.summary())
        sendp(syn, iface=self.outNic)

        sniff(filter="tcp", stop_filter=self.stopParsePackets, store=0, prn=self.parsePackets)

        logging.info("[i] exiting")

        
    def stopParsePackets(self, p):
        if not p.haslayer(TCP) or p[IP].src != self.peerIp:
            return False
        
        if p[TCP].flags == tcpFlags.RST or p[TCP].flags == tcpFlags.FIN + tcpFlags.PSH + tcpFlags.ACK:
            # if TCP packet with flags RST or FIN + PSH + ACK
            logging.info("[+] got FIN or RST packet: %s", p.summary())
            logging.info("[+] peer %s goes Disconnect", self.peerIp)
            return True
       
        if self.getState() == bgpState.ESTABLISHED:
            logging.info("[+] connection to BGP peer was established!")           
            logging.info("[+] peer %s goes Disconnect", self.peerIp)
            return True

        #TODO:
        #if 5 seconds elapsed
        #    return True

        return False


    def parsePackets(self, p):
        if not p.haslayer(IP) or not p.haslayer(TCP):
            #print "[-] not a TCP/IP packet:", p.summary()
            return

        if p[IP].src != self.peerIp or p[TCP].dport != self.srcPort:
            #print "[-] TCP packet not from victim peer:", p.summary()
            return

        if p[TCP].flags == 18 and not self.handshakeOk: 
            logging.info("[+] got SYN+ACK packet: %s", p.summary())
            # got a SYN+ACK, note the peer's seq to use later in BGPOpen and send an ACK now
            ack = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+1, seq=p[TCP].ack, flags="A")
            logging.info("[i] sending ACK packet: %s", ack.summary())
            sendp(ack, iface=self.outNic)	
            self.handshakeOk = True
            logging.info("[+] completed TCP handshake with %s", self.peerIp)

        if self.handshakeOk and not self.bgpOpenSent:
            bgpOpen = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+1, seq=p[TCP].ack, flags="PA") / BGPHeader(type=1) / BGPOpen(version=4, AS=65002, hold_time=180, bgp_id=myIp)
            logging.info("[i] sending BGPOPEN packet: %s", bgpOpen.summary())
            sendp(bgpOpen, iface=self.outNic)
            self.bgpOpenSent = True

        if self.bgpOpenSent and p.haslayer(BGPOpen) and not self.firstKeepAliveSent:
            # got BGPOPEN, acknoledge it and send keepAlive
            logging.info("[+] got BGPOPEN from peer: %s", p.summary())
            pl = BGPHeader(p.getlayer(Raw).load)
            #print "type:", p[BGPHeader].type, "len1:", p[BGPHeader].len, "len2:", pl[BGPHeader].len
            ack2 = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len+pl[BGPHeader].len, seq=p[TCP].ack, flags="A")
            logging.info("[i] sending ACK packet: %s, len: %s", ack2.summary(), p[BGPHeader].len)
            sendp(ack2, iface=self.outNic)
            keepAlive = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len+pl[BGPHeader].len, seq=p[TCP].ack, flags="PA") / BGPHeader(type=4, len=19)
            logging.info("[i] sending first BGPKEEPALIVE packet: %s", keepAlive.summary())
            sendp(keepAlive, iface=self.outNic)
            self.firstKeepAliveSent = True
            return

        if p.haslayer(BGPHeader) and p[BGPHeader].type == 4:
            # got BGPKEEPALIVE, send keep alive and listen for peer's keep alive 
            logging.info("[+] got BGPKEEPALIVE from peer: %s, seq: %s, ack: %s", p.summary(), p[TCP].seq, p[TCP].ack)
            ack2 = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="A")
            logging.info("[i] sending ACK packet: %s", ack2.summary())
            sendp(ack2, iface=self.outNic)
            #if not firstKeepAlive:
            #	keepAlive = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="PA") / BGPHeader(type=4, len=19)
            #	print "[i] sending BGPKEEPALIVE packet:", keepAlive.summary()
            #	sendp(keepAlive, iface=self.outNic)
            #firstKeepAlive = False

        if p.haslayer(BGPHeader) and p[BGPHeader].type == 3:
            logging.info("[+] got BGPNOTIFICATION from peer: %s", p.summary())

        if p.haslayer(BGPHeader) and p[BGPHeader].type == 2:
            logging.info("[+] got BGPUPDATE from peer: %s", p.summary())
            #update={'TYPE':0,'ORIGIN':'\x00','NEXT_HOP':'\x0a\x0a\x0a\x02','MULTI_EXIT_DISC':'\x00\x00\x00\x00','LOCAL_PREF':'\x00\x00\x00\x96','NLRI':[(24, '192.168.2.0')],'AS_PATH':'65002'}
            #updatePacket = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="PA") / Raw(load=update)
            sendp(Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="PA") /
                  BGPHeader(type=2) / BGPUpdate(nlri='192.168.2.0/24',
                                                total_path=[BGPPathAttribute(type='ORIGIN', value='\x00'),
                                                            BGPPathAttribute(type='NEXT_HOP', value='\x0a\x0a\x0a\x02'),
                                                            BGPPathAttribute(flags=128L, type='MULTI_EXIT_DISC', value='\x00\x00\x00\x00'),
                                                            BGPPathAttribute(type='LOCAL_PREF', value='\x00\x00\x00\x96'),
                                                            BGPPathAttribute(type='AS_PATH', value=''),
                                                           ]), iface=self.outNic)			
            #print "[i] sending BGPUPDATE packet:", updatePacket.summary()
            #send(updatePacket)

        
    def getState(self):
        return self.state
    

# need to suppress tcp-rst packets from our machine:
#     sudo iptables -A OUTPUT -p TCP --tcp-flags RST RST -s 10.10.10.2 -j DROP
def suppressTcpRstReplies(ipAddress):
    ruleLabel = "'suppress tcp rst replies'"
    checkIptablesRule = "sudo iptables -nvL | grep " + ruleLabel
    p = subprocess.Popen(checkIptablesRule, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.stdout.readline():
        logging.info("[i] Found tcp rst rule. Do nothing.")
        return
    logging.info("[i] Not found tcp rst rule. Adding one.")
    setIptablesRule = "sudo iptables -A OUTPUT -p TCP --tcp-flags RST RST -s " + ipAddress + " -j DROP -m comment --comment " + ruleLabel
    subprocess.Popen(setIptablesRule, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    
###############################

myIp = "10.10.10.2"
suppressTcpRstReplies(myIp)

p = bgpProbe("ens38", myIp)

peerIp = "10.10.10.1" #"170.104.164.236"
p.connect(peerIp)



















