# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets :)

import time
import socket, sys
from struct import *

class Rule:
    def __init__(self,rule_id, action, protocol, source_ip, source_port, dest_ip, dest_port, message):
        self.protocolDict = {
            "tcp": 6,
            "icmp": 1,
            "udp": 17,
            6: "TCP",
            1: "ICMP",
            17: "UDP"
        }
        self.rule_id = rule_id
        self.action = action 
        self.protocol = protocol
        self.source_ip = source_ip  
        self.source_port = source_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port 
        self.message = message
        
    def matches(self, protocol, source_ip, source_port, dest_ip, dest_port):
        if (protocol==self.protocol):
            if (source_ip==self.source_ip or self.source_ip == "any"):
                if (source_port==self.source_port or self.source_port == "any"):
                    if (dest_ip==self.dest_ip or self.dest_ip == "any"):
                        if (dest_port==self.dest_port or self.dest_port == "any"):
                            return True
                        return False
                    return False
                return False
            return False
        return False
    # def __str__(self):
    #     return "*************\n%s: \n\tProtocol : %s \n\tMessage: %s \n\tSource: %s:%s \n\tDest: %s:%s \n****************\n"%(self.action, self.protocolDict[self.protocol], self.message, str(self.source_ip),str(self.source_port),str(self.dest_ip),str(self.dest_port))
    def fromJson(json):
        return Rule(json["rule_id"],json["action"], json["protocol"], json["source_ip"], json["source_port"], json["dest_ip"], json["dest_port"], json["message"])
        


# a = Rule('Accept',"tcp",'any','any','any','any','tcp packet detected')
# b = Rule('LOG',"udp",'any','any','any','any','udp  packet detected')
# c = Rule('REJECT',"icmp",'any','any','any','any','icmp packet detected')
# rules = [a,b,c]

rule_file = open("./local.rules.json","r")
rules_dict = eval("".join(rule_file.readlines()))
rules = []
for rule_dict in rules_dict["rules"]:
    rules.append(Rule.fromJson(rule_dict))

# print(rules[1])
# print(rules[0])

# sys.exit()


#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

# receive a packet
while True:
    packetBuffer = s.recvfrom(65565)#buffer of the packet
        
    #packet string from tuple
    packet = packetBuffer[0]
   
    
    #parse ethernet header
    eth_header_length = 14
        
    eth_header_raw = packet[:eth_header_length]
    eth_unpacked = unpack('!6s6sH' , eth_header_raw)#()
    eth_protocol = socket.ntohs(eth_unpacked[2])

    
    # Check if a the protocol is IP
    # Parse IP packets, IP Protocol number = 8  => IPV4
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_header_length:20+eth_header_length]
        
        """
        IP header size >=20 bytes
        ++++++++++++++++++++++++++++++++++++++++++++++++++++++
        + version(1 byte) | IHL(internet header length)(1 byte) | DSCP(6 bits) 
        + ECN(2 bits) | Total Length(2 bytes) | ID(2 bytes) |  flags(3 bits)  
        + Fragment offset(13 bits) | Time to live (1 byte) | protocol (1 byte) 
        + checksum(2 bytes) | source ip (4 bytes) | destination ip (4 bytes)  
        + options (if HL > 5)
        ++++++++++++++++++++++++++++++++++++++++++++++++++++++
        """
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        # TODO caution hardcoded header length
        version_ihl = iph[0]
        # # version = version_ihl >> 4
        
        ihl = version_ihl & 0xF
        # print(ihl)
        ip_header_length = ihl*4
        # print(ip_header_length)
        
        protocol = iph[6]
        
        # convert integer form of ip address to period separated form of ip address
        source_ip = socket.inet_ntoa(iph[8]);
        dest_ip = socket.inet_ntoa(iph[9]);

        
        #TCP protocol
        if protocol == 6 :
            """
            TCP header size = 20 bytes
            ++++++++++++++++++++++++++++++++++++++++++++++++++++++
            |source_port(2 bytes) | dest_port(2 bytes) | sequence(4 bytes) | acknowledgement(4 bytes) | doff_reserved (1 byte) | ....
            ++++++++++++++++++++++++++++++++++++++++++++++++++++++
            """
            tcp_header_start = ip_header_length + eth_header_length
            tcp_header_packed = packet[tcp_header_start : tcp_header_start+20]

            #now unpack them :)
            tcp_header_unpacked = unpack('!HHLLBBHHH' , tcp_header_packed)

            
            source_port = tcp_header_unpacked[0]
            dest_port = tcp_header_unpacked[1]
            for rule in rules:
                if (rule.matches("tcp", source_ip, source_port, dest_ip, dest_port)):
                    print("*************\n%s: \n\tProtocol : %s \n\tMessage: %s \n\tSource: %s:%s \n\tDest: %s:%s \n****************\n"%(rule.action, rule.protocolDict[rule.protocol], rule.message, str(source_ip),str(source_port),str(dest_ip),str(dest_port)))
                    
                   

        #ICMP Packets
        elif protocol == 1 :
            # ICMP DOESNOT USE A PORT NUMBER
            """
            ICMP header size  = 4 bytes
            ++++++++++++++++++++++++++++++++++++++++++++++++++++++
            | Type (1 byte) | Code (1 byte) | Checksum (2 bytes) |            
            ++++++++++++++++++++++++++++++++++++++++++++++++++++++
            """
            icmp_header_start = ip_header_length + eth_header_length
            icmp_header_length = 4
            icmp_header_raw = packet[icmp_header_start : icmp_header_start+4]

            # unpack the raw bytes
            icmp_header_unpacked = unpack('!BBH' , icmp_header_raw)
            
            
            icmp_type = icmp_header_unpacked[0]
            
            # print(str(source_ip))
            # print(str(dest_ip))
            for rule in rules:
                if (rule.matches("icmp", source_ip,"any", dest_ip,"any")):
                    print("*************\n%s: \n\tProtocol : %s \n\tMessage: %s \n\tSource: %s \n\tDest: %s\n"%(rule.action, rule.protocolDict[rule.protocol], rule.message, str(source_ip),str(dest_ip)),'ICMP type : ' + str(icmp_type)+"\n****************\n")
                    
            
            

        # UDP packets
        elif protocol == 17 :
            """
            UDP header size = 8 bytes
            ++++++++++++++++++++++++++++++++++++++++++++++++++++
            + Source port(2 bytes) | Destination port (2 bytes)+
            + Length (2 bytes)     | Checksum (2 bytes)        +
            ++++++++++++++++++++++++++++++++++++++++++++++++++++
            """

            udp_header_start = ip_header_length + eth_header_length
            
            udp_header_raw = packet[udp_header_start : udp_header_start + 8]

            #now unpack them :)
            udp_header_unpacked = unpack('!HHHH' , udp_header_raw)
            
            source_port = udp_header_unpacked[0]
            dest_port = udp_header_unpacked[1]
            
            
            # print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) )
            # break
            for rule in rules:
                if (rule.matches("udp", source_ip, source_port, dest_ip, dest_port)):
                    print("*************\n%s: \n\tProtocol : %s \n\tMessage: %s \n\tSource: %s:%s \n\tDest: %s:%s \n****************\n"%(rule.action, rule.protocolDict[rule.protocol], rule.message, str(source_ip),str(source_port),str(dest_ip),str(dest_port)))

    
        

        time.sleep(1)