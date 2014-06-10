#! /usr/bin/python

# Copyright (c) 2014 Andrius Aucinas <andrius.aucinas@cl.cam.ac.uk>
# 
# Permission to use, copy, modify, and distribute this software for any
# rpose with or without fee is hereby granted, provided that the above
# pyright notice and this permission notice appear in all copies.
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from scapy.all import *
import pprint
import threading
import Queue

connectionInfo = {}
connectionTest = {}

def hexdump(x):
  x = str(x)
  l = len(x)
  i = 0
  result = ""
  while i < l:
    result += '{:04X}'.format(i) + "   "
    for j in range(16):
      if i+j < l:
        result += '{:02X}'.format(ord(x[i+j]))
      else:
        result += "   "
      if j%16 == 7:
        result += " "
    result += "  "
    result += sane_color(x[i:i+16]) + "\n"
    i += 16
  return result

def ip2int(addr):                                                               
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def checksum_add(checksum, val):
    checksum = checksum + val
    checksum = (checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF);
    return checksum

def checksum_sub(checksum, val):
    return checksum_add(checksum, (~val)&0xFFFF);

def checksum_add_32(checksum, val):
    return checksum_add(checksum_add(checksum, val & 0xFFFF), (val >> 16) & 0xFFFF)

def checksum_sub_32(checksum, val):
    return checksum_add_32(checksum, ~val)

def longToStr(val):
  return chr( (val>>(8*3)) & 0xFF ) + chr( (val>>(8*2)) & 0xFF ) + chr( (val>>(8*1)) & 0xFF ) + chr( (val>>(8*0)) & 0xFF )

def shortToStr(val):
  return chr( (val>>(8*1)) & 0xFF ) + chr( (val>>(8*0)) & 0xFF )

def process_packet(pkt_in):
  dst = pkt_in[IP].src
  src = pkt_in[IP].dst
  dport = pkt_in[TCP].sport
  sport = pkt_in[TCP].dport
  ip = IP(dst=dst, src=src)

  connID = dst + str(dport)
  connStatus = connectionInfo.get(connID, TCPCState.CLOSED)
  logfile = open(dst+".log", "a")
  if (connStatus != TCPCState.CLOSED):
    logfile.write("<---- Packet received from " + dst + ":" + str(dport) + " to " + src + ":" + str(sport) + "\n")
    logfile.write(hexdump(pkt_in))

  if (pkt_in[TCP].flags == 0x02):
    if (connStatus != TCPCState.CLOSED):
    	logfile.write("\tConnection already exists!" + "\n")
    connectionInfo[connID] = TCPCState.SYN_RECEIVED
    pak = None

    if (pkt_in[TCP].ack == 0xbeef0001):
      logfile.write("\n\n--- TESTCASE 0xbeef0001 ---" + "\n")
      connectionTest[connID] = 1
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1)
      pak=ip/SYNACK

    elif (pkt_in[TCP].urgptr == 0xbe02):
      logfile.write("\n\n--- TESTCASE 0xbe02 ---" + "\n")
      connectionTest[connID] = 2
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1)
      pak=ip/SYNACK

    elif (pkt_in[TCP].ack == 0xbeef0003):
      logfile.write("\n\n--- TESTCASE 0xbeef0003 ---" + "\n")
      connectionTest[connID] = 3
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1, urgptr=0xbe03)
      pak=ip/SYNACK

    elif (pkt_in[TCP].ack == 0xbeef0005 or pkt_in[TCP].urgptr == 0xbe09):
      if (pkt_in[TCP].ack == 0xbeef0005):
        logfile.write("\n\n--- TESTCASE 0xbeef0005 ---" + "\n")
      elif (pkt_in[TCP].urgptr == 0xbe09):
        logfile.write("\n\n--- TESTCASE 0xbe09 ---" + "\n")
      connectionTest[connID] = 9
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1)
      pak=ip/SYNACK
      checksum = 0xbeef
      checksum = checksum_sub_32(checksum, ip2int(dst))
      checksum = checksum_sub(checksum, dport)
      logfile.write("SYNACK with checksum " + hex(checksum) + "\n")
      # Force TCP checksum to be recalculated
      del pak[TCP].chksum
      pak[TCP].chksum = checksum

    elif (pkt_in[TCP].ack == 0xbeef000D):
      logfile.write("\n\n--- TESTCASE 0xbeef000D ---" + "\n")
      connectionTest[connID] = 8
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1)
      pak=ip/SYNACK
      # Different checksum to differentiate when which type of rewriting happens
      checksum = 0xbeee
      checksum = checksum_sub_32(checksum, ip2int(dst))
      checksum = checksum_sub(checksum, dport)
      checksum = checksum_sub_32(checksum, SYNACK.seq)
      checksum = checksum_sub_32(checksum, SYNACK.ack)
      logfile.write("SYNACK with checksum " + hex(checksum) + "\n")
      # Force TCP checksum to be recalculated
      del pak[TCP].chksum
      pak[TCP].chksum = checksum


    elif (pkt_in[TCP].ack == 0xbeef0006 or pkt_in[TCP].urgptr == 0xbe08):
      if (pkt_in[TCP].ack == 0xbeef0006):
        logfile.write("\n\n--- TESTCASE 0xbeef0006 ---" + "\n")
      elif (pkt_in[TCP].urgptr == 0xbe08):
        logfile.write("\n\n--- TESTCASE 0xbe05 ---" + "\n")
      connectionTest[connID] = 6
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1)
      pak=ip/SYNACK
      checksum = 0xbeef
      checksum = checksum_sub_32(checksum, ip2int(dst))
      checksum = checksum_sub(checksum, dport)
      # Force TCP checksum to be recalculated
      del pak[TCP].chksum
      # Checksum calculated when converting packet to string..
      packet = pak.__class__(str(pak))
      # Difference between the current checksum and the desired one, also payload length
      chksumDiff = checksum_sub(checksum_sub(packet[TCP].chksum, checksum), 2)
      pak = pak/struct.pack('>H', chksumDiff)
      logfile.write("SYNACK with checksum " + hex(checksum) + " and payload for validity" + "\n")

    elif (pkt_in[TCP].urgptr == 0xbe07):
      logfile.write("\n\n--- TESTCASE 0xbe07 ---" + "\n")
      connectionTest[connID] = 7
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1, urgptr=0xbe07)
      pak=ip/SYNACK

    elif(pkt_in[TCP].reserved > 0):
      logfile.write("\n\n--- TESTCASE SYN RESERVED ---" + "\n")
      logfile.write("SYN packet with reserved " + str(pkt_in[TCP].reserved) + "\n")
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1, reserved=pkt_in[TCP].reserved)
      pak=ip/SYNACK

    else:
      logfile.write("\n\n--- TESTCASE 0xbe04 ---" + "\n")
      logfile.write("Default SYNACK, for packet with ACK = " + hex(pkt_in[TCP].ack) + "\n")
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1, urgptr=0xbe04)
      pak=ip/SYNACK
    
    logfile.write("\t(SYN packet)" + "\n")
    logfile.write("<---- Packet received from " + dst + ":" + str(dport) + " to " + src + ":" + str(sport) + "\n")
    logfile.write(hexdump(pkt_in))
    logfile.write("----> Response" + "\n")
    logfile.write(hexdump(pak))
    return pak

  elif (pkt_in[TCP].flags & 0x01):
    logfile.write("Closing, FIN" + "\n")
    logfile.write("----------------" + "\n")
    # Remove connection from the dictionary
    connectionInfo[connID] = TCPCState.LAST_ACK
    FINACK=TCP(sport=sport, dport=dport, flags="FA", seq=pkt_in[TCP].ack, ack=pkt_in[TCP].seq + 1)
    pak=ip/FINACK
    logfile.write("----> Response" + "\n")
    logfile.write(hexdump(pak))
    return pak

  elif (pkt_in[TCP].flags == 0x10 and not Raw in pkt_in):
    logfile.write("ACK empty" + "\n")
    if (connStatus == TCPCState.SYN_RECEIVED):
    	logfile.write("Empty ACK in handshake" + "\n")
    	connectionInfo[connID] = TCPCState.ESTABLISHED
    elif (connStatus == TCPCState.LAST_ACK):
      logfile.write("Last ACK, connection closed" + "\n")
      logfile.write("----------------" + "\n")
      del connectionInfo[connID]
    return None

  elif (Raw in pkt_in): 
    logfile.write("Payload: " + pkt_in[Raw].load + ", len = " + str(len(pkt_in[Raw].load)) + "\n")
    if (connStatus != TCPCState.ESTABLISHED):
    	logfile.write("Packet with payload but no connection" + "\n")
    if (pkt_in[TCP].reserved > 0):
      logfile.write("Data packet reserved field: " + str(pkt_in[TCP].reserved) + "\n")
    ACK=TCP(sport=sport, dport=dport, flags="A", seq=pkt_in[TCP].ack, ack=pkt_in[TCP].seq+len(pkt_in[Raw].load), reserved=pkt_in[TCP].reserved)
    payload = ""
    currentTest = connectionTest.get(connID, 0)
    if (currentTest == 1):
      payload = longToStr(0xbeef0001)
    elif (currentTest == 2):
      payload = shortToStr(0xbe02)
    elif (pkt_in[Raw].load == "GETMYIP"):
      payload = longToStr(ip2int(ip.dst))
    else:
      payload = "OLLEH"
    pak=ip/ACK/payload
    logfile.write("----> Response" + "\n")
    logfile.write(hexdump(pak))
    return pak

class TCPCState:
  (LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED, 
  FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, 
  LAST_ACK, TIME_WAIT, CLOSED) = range(1,12)

class PacketProcessor(threading.Thread):
  def __init__(self, queue, send_queue):
    self.__queue = queue
    self.__send_queue = send_queue
    threading.Thread.__init__(self)

  def run(self):
    while 1:
      # print "Waiting for packet"
      packet = self.__queue.get()
      reply = process_packet(packet)
      if reply is not None:
        self.__send_queue.put(reply)

class PacketSender(threading.Thread):
  def __init__(self, queue):
    self.__queue = queue
    threading.Thread.__init__(self)

  def run(self):
    while 1:
      # print "Getting packet to send"
      packet = self.__queue.get()
      send(packet)

receive_queue = Queue.Queue(0)
send_queue = Queue.Queue(0)

processor = PacketProcessor(receive_queue, send_queue)
sender = PacketSender(send_queue)
processor.daemon = True
processor.start()
sender.daemon = True
sender.start()

sniff(prn=receive_queue.put, filter="tcp and dst 192.95.61.161 and (dst port 6969 or dst port 80 or dst port 443 or dst port 8080 or dst port 8000 or dst port 445 or dst port 993 or dst port 139 or dst port 5228)", store=0)
