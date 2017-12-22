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
os.sys.path.insert(1, './scapy')

# for setting iptables to suppress output tcp rst packets
import subprocess 
import time

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.bgp import *

import logging
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO) #, filename='myapp.log')

bgpLog = logging.getLogger("bgpProbe")
bgpLog.setLevel(logging.CRITICAL) # comment this line to enable logs

mainLog = logging.getLogger("mainLog")
#mainLog.setLevel(logging.CRITICAL) # comment this line to enable logs

import argparse


class tcpFlags:
    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16
    URG = 32

class bgpState:
    IDLE = "IDLE"
    CONNECT = "CONNECT"
    ACTIVE = "ACTIVE"
    OPENSENT = "OPENSENT"
    OPENCONFIRMED = "OPENCONFIRMED"
    ESTABLISHED = "ESTABLISHED"

class bgpProbe:
    
    def __init__(self, outNic, myIp):
        self.outNic = outNic
        self.myIp = myIp
        self.timeOut = 5
        self.suppressTcpRstReplies()
        
        
    def resetParams(self):
        self.srcPort = random.randint(40000, 65535)
        self.randomSeq = int(RandInt())
        self.handshakeOk = False
        self.bgpOpenSent = False
        self.firstKeepAliveSent = False
        self.state = bgpState.IDLE
        self.peerIp = "0.0.0.0"
        self.startTime = 0       
        
        
    def connect(self, peerIp):
        self.resetParams()
        self.startTime = time.time()
        self.peerIp = peerIp
        bgpLog.info("\n")
        bgpLog.info("[i] trying to connect to %s", self.peerIp)

        syn = Ether() / IP(dst=self.peerIp, id=int(RandShort())) / TCP(sport=self.srcPort, dport=179, ack=0, seq=self.randomSeq, flags="S")
        bgpLog.info("[i] sending SYN packet: %s", syn.summary())
        sendp(syn, iface=self.outNic, verbose=0)

        self.state = bgpState.CONNECT

        sniff(iface=self.outNic, filter="ether", stop_filter=self.stopParsePackets, store=0, prn=self.parsePackets)

        bgpLog.info("[i] exiting with probe state: %s", self.getState())

        
    def stopParsePackets(self, p):
        currentTime = time.time();
        if (currentTime - self.startTime >= self.timeOut):
            bgpLog.info("[i] exit due to timeout: %s seconds", self.timeOut)
            return True
        
        if not p.haslayer(TCP) or p[IP].src != self.peerIp:
            return False
        
        if (p[TCP].flags == tcpFlags.RST or 
            p[TCP].flags == tcpFlags.RST + tcpFlags.ACK or
            p[TCP].flags == tcpFlags.RST + tcpFlags.ACK + tcpFlags.FIN
           ):
            # if TCP packet with flags RST or FIN + PSH + ACK
            bgpLog.info("[+] got FIN or RST packet: %s", p.summary())
            bgpLog.info("[+] peer %s goes Disconnect", self.peerIp)
            return True
       
        if self.getState() == bgpState.ESTABLISHED:
            bgpLog.info("[+] connection to BGP peer was established!")           
            bgpLog.info("[+] peer %s goes Disconnect", self.peerIp)
            return True

        return False


    def parsePackets(self, p):
        if not p.haslayer(IP) or not p.haslayer(TCP):
            #print "[-] not a TCP/IP packet:", p.summary()
            return

        if p[IP].src != self.peerIp or p[TCP].dport != self.srcPort:
            #print "[-] TCP packet not from victim peer:", p.summary()
            return

        if p[TCP].flags == 18 and not self.handshakeOk: 
            bgpLog.info("[+] got SYN+ACK packet: %s", p.summary())
            # got a SYN+ACK, note the peer's seq to use later in BGPOpen and send an ACK now
            ack = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+1, seq=p[TCP].ack, flags="A")
            bgpLog.info("[i] sending ACK packet: %s", ack.summary())
            sendp(ack, iface=self.outNic, verbose=0)	
            self.handshakeOk = True
            bgpLog.info("[+] completed TCP handshake with %s", self.peerIp)
            self.state = bgpState.ACTIVE

        if self.handshakeOk and not self.bgpOpenSent:
            bgpOpen = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+1, seq=p[TCP].ack, flags="PA") / BGPHeader(type=1) / BGPOpen(version=4, AS=65002, hold_time=180, bgp_id=self.myIp)
            bgpLog.info("[i] sending BGPOPEN packet: %s", bgpOpen.summary())
            sendp(bgpOpen, iface=self.outNic, verbose=0)
            self.bgpOpenSent = True
            self.state = bgpState.OPENSENT

        if self.bgpOpenSent and p.haslayer(BGPOpen) and not self.firstKeepAliveSent:
            # got BGPOPEN, acknoledge it and send keepAlive
            bgpLog.info("[+] got BGPOPEN from peer: %s", p.summary())
            self.state = bgpState.OPENCONFIRMED
            pl = BGPHeader(p.getlayer(Raw).load)
            #print "type:", p[BGPHeader].type, "len1:", p[BGPHeader].len, "len2:", pl[BGPHeader].len
            ack2 = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len+pl[BGPHeader].len, seq=p[TCP].ack, flags="A")
            bgpLog.info("[i] sending ACK packet: %s, len: %s", ack2.summary(), p[BGPHeader].len)
            sendp(ack2, iface=self.outNic, verbose=0)
            keepAlive = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len+pl[BGPHeader].len, seq=p[TCP].ack, flags="PA") / BGPHeader(type=4, len=19)
            bgpLog.info("[i] sending first BGPKEEPALIVE packet: %s", keepAlive.summary())
            sendp(keepAlive, iface=self.outNic, verbose=0)
            self.firstKeepAliveSent = True
            return

        if p.haslayer(BGPHeader) and p[BGPHeader].type == 4:
            # got BGPKEEPALIVE, send keep alive and listen for peer's keep alive 
            bgpLog.info("[+] got BGPKEEPALIVE from peer: %s, seq: %s, ack: %s", p.summary(), p[TCP].seq, p[TCP].ack)
            ack2 = Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="A")
            bgpLog.info("[i] sending ACK packet: %s", ack2.summary())
            sendp(ack2, iface=self.outNic, verbose=0)

        if p.haslayer(BGPHeader) and p[BGPHeader].type == 3:
            bgpLog.info("[+] got BGPNOTIFICATION from peer: %s", p.summary())

        if p.haslayer(BGPHeader) and p[BGPHeader].type == 2:
            bgpLog.info("[+] got BGPUPDATE from peer: %s", p.summary())
            sendp(Ether() / IP(dst=p[IP].src, id=int(RandShort())) / TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq+p[BGPHeader].len, seq=p[TCP].ack, flags="PA") /
                  BGPHeader(type=2) / BGPUpdate(nlri='192.168.2.0/24',
                                                total_path=[BGPPathAttribute(type='ORIGIN', value='\x00'),
                                                            BGPPathAttribute(type='NEXT_HOP', value='\x0a\x0a\x0a\x02'),
                                                            BGPPathAttribute(flags=128L, type='MULTI_EXIT_DISC', value='\x00\x00\x00\x00'),
                                                            BGPPathAttribute(type='LOCAL_PREF', value='\x00\x00\x00\x96'),
                                                            BGPPathAttribute(type='AS_PATH', value=''),
                                                           ]), iface=self.outNic, verbose=0)			
            #print "[i] sending BGPUPDATE packet:", updatePacket.summary()
            #send(updatePacket)
            self.state = bgpState.ESTABLISHED

        
    def getState(self):
        return self.state
        
    
    # need to suppress tcp-rst packets from our machine:
    #     sudo iptables -A OUTPUT -p TCP --tcp-flags RST RST -s 10.10.10.2 -j DROP
    def suppressTcpRstReplies(self):
        ruleLabel = "'suppress tcp rst replies'"
        checkIptablesRule = "sudo iptables -nvL | grep " + ruleLabel
        p = subprocess.Popen(checkIptablesRule, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if p.stdout.readline():
            bgpLog.info("[i] found tcp rst rule. Do nothing.")
            return
        bgpLog.info("[i] not found tcp rst rule. Adding one.")
        setIptablesRule = "sudo iptables -A OUTPUT -p TCP --tcp-flags RST RST -s " + self.myIp + " -j DROP -m comment --comment " + ruleLabel
        subprocess.Popen(setIptablesRule, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    
#########################################################

#TODO: run tcpdump in background thread:
#    sudo tcpdump -i ens38 -s 65535 -w output.pcap


def main():
    # parse command line
    parser = argparse.ArgumentParser(prog="bgpProbe", description="Tries to connect to BGP routers.")
    parser.add_argument("-n", metavar="out_iface", help="output network interface name", required=True)
    parser.add_argument("-i", metavar="out_ip", help="output ip address, it'll be the source address", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", metavar="file_with_ips", help="file containing ip addresses separated by \n")
    group.add_argument("-t", metavar="target_ip", help="ip address to be probed", nargs="+")
    args = parser.parse_args()
        
    outFile = open("./bgpprobes.txt", "w")
    
    try:
        # read ips list
        ips = []
        if args.f != None:
            mainLog.info("[i] started reading file")
            inFile = open(args.f, "r")
            for line in inFile:
                ips.append(line[:-1]) # remove the last newline in the string
            inFile.close()
            mainLog.info("[+] stopped reading file")
        else:
            ips = args.t
            
        # create bgpProbe instance
        p = bgpProbe(args.n, args.i)

        totalCount = len(ips)
        count = 1
        
        # main scanning loop
        mainLog.info("[i] going to scan %s ips", totalCount)
        for ip in ips:
            print("")
            mainLog.info("[i] started bgpProbe on peer %s (%s of %s)", ip, count, totalCount)
            p.connect(ip)
            mainLog.info("[+] finished bgpProbe on peer %s with state %s", ip, p.getState())
            outFile.write(ip + "," + p.getState() + "\n")
            count += 1

    finally:
        outFile.close()
        mainLog.info("[i] clean up and exit")
        return 0
    
    
if __name__ == "__main__":
    sys.exit(main())





















