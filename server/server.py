#! /usr/bin/python

from scapy.all import *
import pprint
import threading
import Queue

connectionInfo = {}
connectionTest = {}

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

  if (pkt_in[TCP].flags == 0x02):
    print "SYN"
    if (connStatus == TCPCState.CLOSED):
    	print "Connection already exists"
    connectionInfo[connID] = TCPCState.SYN_RECEIVED

    pak = None

    if (pkt_in[TCP].ack == 0xbeef0001):
      connectionTest[connID] = 1
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1)
      pak=ip/SYNACK

    elif (pkt_in[TCP].urgptr == 0xbe02):
      connectionTest[connID] = 2
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1)
      pak=ip/SYNACK

    elif (pkt_in[TCP].ack == 0xbeef0003):
      connectionTest[connID] = 3
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1, urgptr=0xbe03)
      pak=ip/SYNACK

    elif (pkt_in[TCP].ack == 0xbeef0005 or pkt_in[TCP].urgptr == 0xbe09):
      connectionTest[connID] = 9
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1)
      pak=ip/SYNACK
      checksum = 0xbeef
      checksum = checksum_sub_32(checksum, ip2int(dst))
      checksum = checksum_sub(checksum, dport)
      print "SYNACK with checksum " + hex(checksum)
      # Force TCP checksum to be recalculated
      del pak[TCP].chksum
      pak[TCP].chksum = checksum

    elif (pkt_in[TCP].ack == 0xbeef000D):
      connectionTest[connID] = 8
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1)
      pak=ip/SYNACK
      # Different checksum to differentiate when which type of rewriting happens
      checksum = 0xbeee
      checksum = checksum_sub_32(checksum, ip2int(dst))
      checksum = checksum_sub(checksum, dport)
      checksum = checksum_sub_32(checksum, SYNACK.seq)
      checksum = checksum_sub_32(checksum, SYNACK.ack)
      print "SYNACK with checksum " + hex(checksum)
      # Force TCP checksum to be recalculated
      del pak[TCP].chksum
      pak[TCP].chksum = checksum


    elif (pkt_in[TCP].ack == 0xbeef0006 or pkt_in[TCP].urgptr == 0xbe05):
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
      print "SYNACK with checksum " + hex(checksum) + " and payload for validity"

    elif (pkt_in[TCP].urgptr == 0xbe07):
      connectionTest[connID] = 7
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1, urgptr=0xbe07)
      pak=ip/SYNACK

    elif(pkt_in[TCP].reserved > 0):
      print "SYN packet with reserved " + str(pkt_in[TCP].reserved)
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1, reserved=pkt_in[TCP].reserved)
      pak=ip/SYNACK

    else:
      print "Default SYNACK, for packet with ACK = " + hex(pkt_in[TCP].ack)
      SYNACK=TCP(sport=sport, dport=dport, flags="SA", seq=12345, ack=pkt_in[TCP].seq+1, urgptr=0xbe04)
      pak=ip/SYNACK
      
    return pak

  elif (pkt_in[TCP].flags & 0x01):
    print "Closing, FIN"
    # Remove connection from the dictionary
    connectionInfo[connID] = TCPCState.LAST_ACK
    FINACK=TCP(sport=sport, dport=dport, flags="FA", seq=pkt_in[TCP].ack, ack=pkt_in[TCP].seq + 1)
    pak=ip/FINACK
    return pak

  elif (pkt_in[TCP].flags == 0x10 and not Raw in pkt_in):
    print "ACK empty"
    if (connStatus == TCPCState.SYN_RECEIVED):
    	print "Empty ACK in handshake"
    	connectionInfo[connID] = TCPCState.ESTABLISHED
    elif (connStatus == TCPCState.LAST_ACK):
      print "Last ACK, connection closed"
      del connectionInfo[connID]
    return None

  elif (Raw in pkt_in): 
    print "Payload: " + pkt_in[Raw].load + ", len = " + str(len(pkt_in[Raw].load))
    if (connStatus != TCPCState.ESTABLISHED):
    	print "Packet with payload but no connection"
    if (pkt_in[TCP].reserved > 0):
      print "Data packet reserved field: " + str(pkt_in[TCP].reserved)
    ACK=TCP(sport=sport, dport=dport, flags="A", seq=pkt_in[TCP].ack, ack=pkt_in[TCP].seq+len(pkt_in[Raw].load), reserved=pkt_in[TCP].reserved)
    payload = ""
    currentTest = connectionTest.get(connID, 0)
    if (currentTest == 1):
      payload = longToStr(0xbeef0001)
    elif (currentTest == 2):
      payload = shortToStr(0xbe02)
    else:
      payload = "OLLEH"
    pak=ip/ACK/payload
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
      print "Waiting for packet"
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
      print "Getting packet to send"
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

sniff(prn=receive_queue.put, filter="tcp and dst port 6969", store=0)
