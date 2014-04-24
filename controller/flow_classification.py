from pyretic.lib.corelib import *
from pyretic.lib.query import *
from libprotoident import *
import struct
from recordtype import recordtype
import socket

PacketStruct = recordtype("PacketStruct",
                          "packet raw_bytes eth_payload_bytes ip_version ip_header_len ip_payload_bytes ip_proto tcp_data_offset tcp_header_len tcp_payload_bytes udp_header_len udp_payload_bytes lpi_payload")


class flow_classification(DynamicPolicy):
    brdn = 8796759375755
    brup = 8796758988785

    port_dn_2 = 2
    port_dn_3 = 3
    port_dn_4 = 4
    port_dn_5 = 5

    port_up_2 = 2
    port_up_3 = 3
    port_up_4 = 4
    port_up_5 = 5

    homePrefix = IPPrefix("10.0.2.0/24")

    flowFirstPackets = {}

    classifiedFlows = {}

    handledFlows = set()

    videoSites = set()

    videoSitesIp = set()

    def __init__(self):
        super(flow_classification, self).__init__()

        self.forward = if_(match(switch=self.brup, inport=1), fwd(self.port_up_5),
                           if_(match(switch=self.brup, inport=self.port_up_5), fwd(1),
                               if_(match(switch=self.brdn, inport=1), fwd(self.port_dn_5),
                                   if_(match(switch=self.brdn, inport=self.port_dn_5), fwd(1), drop))))

        # we need the third packet to identify web traffic...
        self.query_filter = (match(ethtype=IP_TYPE, protocol=0x06) | match(ethtype=IP_TYPE, protocol=0x11)) \
                            & (~(match(srcport=53) | match(dstport=53))) & (match(switch=self.brdn))
        self.query = packets(limit=3, group_by=['srcip', 'dstip', 'protocol', 'srcport', 'dstport'])

        self.query.register_callback(self.analyzer)

        self.query = self.query_filter >> self.query

        self.update_policy()

        # read in video-sites from file:
        fp = open("videoSites")
        for i, line in enumerate(fp):
            self.videoSites.add(line)
        fp.close()

        fp = open("videoSitesIp")
        for i, line in enumerate(fp):
            self.videoSitesIp.add(IPPrefix(line))
        fp.close()

    def update_policy(self):
        self.policy = self.forward + self.query

    def printClassificationTable(self):
        print "Classifications:"
        for key, classification in self.classifiedFlows.iteritems():
            print "%s: %s" % (key, classification)

    def isVideoSite(self, hostname):
        # get rid of www, might mess things up...
        hostname = hostname.replace('www.', '')
        for videoSite in self.videoSites:
            if videoSite in hostname:
                return True
        return False

    def isVideoSiteIp(self, ip):
        for videoSiteIp in self.videoSitesIp:
            if videoSiteIp == ip:
                return True
        return False

    @staticmethod
    def analyzePacket(packet):
        retPkt = PacketStruct("", [], [], 0, 0, "", 0, 0, 0, [], 0, [], 0)
        retPkt.packet = packet
        if packet['ethtype'] == IP_TYPE:
            retPkt.raw_bytes = [ord(c) for c in packet['raw']]
            retPkt.eth_payload_bytes = retPkt.raw_bytes[packet['header_len']:]

            retPkt.ip_version = (retPkt.eth_payload_bytes[0] & 0b11110000) >> 4
            ihl = (retPkt.eth_payload_bytes[0] & 0b00001111)
            retPkt.ip_header_len = ihl * 4
            retPkt.ip_payload_bytes = retPkt.eth_payload_bytes[retPkt.ip_header_len:]
            retPkt.ip_proto = retPkt.eth_payload_bytes[9]

            if retPkt.ip_proto == 0x06:
                retPkt.tcp_data_offset = (retPkt.ip_payload_bytes[12] & 0b11110000) >> 4
                retPkt.tcp_header_len = retPkt.tcp_data_offset * 4
                retPkt.tcp_payload_bytes = retPkt.ip_payload_bytes[retPkt.tcp_header_len:]

                if len(retPkt.tcp_payload_bytes) >= 4:
                    payloadFirstFourBytes = retPkt.tcp_payload_bytes[0:4]
                    # print payloadFirstFourBytes
                    payloadFirstFourBytes.reverse()

                    retPkt.lpi_payload = struct.unpack(">I", ''.join(
                        [chr(x) for x in payloadFirstFourBytes]))
                    retPkt.lpi_payload = retPkt.lpi_payload[0]

            elif retPkt.ip_proto == 0x11:
                retPkt.udp_header_len = 8
                retPkt.udp_payload_bytes = retPkt.ip_payload_bytes[retPkt.udp_header_len:]
                if len(retPkt.udp_payload_bytes) >= 4:
                    payloadFirstFourBytes = retPkt.udp_payload_bytes[0:4]
                    payloadFirstFourBytes.reverse()

                    retPkt.lpi_payload = struct.unpack(">I", ''.join(
                        [chr(x) for x in payloadFirstFourBytes]))
                    retPkt.lpi_payload = retPkt.lpi_payload[0]

            if retPkt.lpi_payload == "":
                retPkt.lpi_payload = 0

        return retPkt

    @staticmethod
    def printPacket(packet):
        print "------packet--------"
        print packet.packet
        if packet.packet['ethtype'] == IP_TYPE:
            print "ethernet payload is %d" % packet.packet['payload_len']
            print "ethernet payload is %d bytes" % len(packet.eth_payload_bytes)
            print "ip_version = %d" % packet.ip_version
            print "ip_header_len = %d" % packet.ip_header_len
            print "ip_proto = %d" % packet.ip_proto
            print "ip payload is %d bytes" % len(packet.ip_payload_bytes)
            if packet.ip_proto == 0x06:
                print "tcp_header_len = %d" % packet.tcp_header_len
                print "tcp payload is %d bytes" % len(packet.tcp_payload_bytes)
                if len(packet.tcp_payload_bytes) > 0:
                    print "payload:\t",
                    print ''.join([chr(d) for d in packet.tcp_payload_bytes])
            elif packet.ip_proto == 0x11:
                print "udp_header_len = %d" % packet.udp_header_len
                print "udp payload is %d bytes" % len(packet.udp_payload_bytes)
                if len(packet.udp_payload_bytes) > 0:
                    print "payload:\t",
                    print ''.join([chr(d) for d in packet.udp_payload_bytes])
            elif packet.ip_proto == 0x01:
                print "ICMP packet"
            else:
                print "Unhandled packet type"

            print packet.ip_payload_bytes
            print packet.lpi_payload
            print packet.packet['srcip']
            print packet.packet['dstip']
            print packet.packet['srcport']
            print packet.packet['dstport']
            print packet.packet['payload_len']
            print packet.packet['payload_len']
            print packet.ip_proto

    def analyzeFlow(self, packetOut, packetIn):
        return lpi_shim_guess_protocol(packetIn.lpi_payload, packetOut.lpi_payload,
                                       self.ip2int(packetIn.packet['srcip']),
                                       self.ip2int(packetIn.packet['dstip']),
                                       packetIn.packet['srcport'], packetIn.packet['dstport'],
                                       packetIn.packet['payload_len'],
                                       packetIn.packet['payload_len'],
                                       packetIn.packet['protocol'])

    @staticmethod
    def generateKey(packet, switched=false):
        if not switched:
            return str(packet.packet['srcip']) + "-" + str(packet.packet['dstip']) + "-" + str(
                packet.packet['srcport']) + "-" + str(packet.packet['dstport']) + "-" + str(packet.packet['protocol'])

        return str(packet.packet['dstip']) + "-" + str(packet.packet['srcip']) + "-" + str(
            packet.packet['dstport']) + "-" + str(packet.packet['srcport']) + "-" + str(packet.packet['protocol'])

    def keyInMap(self, key):
        return key in self.flowFirstPackets

    def putPacket(self, packet):
        key = self.generateKey(packet)
        if len(packet.tcp_payload_bytes) > 0 or len(packet.udp_payload_bytes) > 0:
            if key not in self.flowFirstPackets:
                self.flowFirstPackets[key] = packet

    def getMatchingPacket(self, packet):
        # switch srcip and destip, as well as srcport and dstport...
        key = self.generateKey(packet, true)
        if key in self.flowFirstPackets:
            # print key
            return self.flowFirstPackets[key]
        return ""

    def analyzer(self, pkt):
        packet = self.analyzePacket(pkt)
        key = self.generateKey(packet, true)
        if key not in self.handledFlows:
            if len(packet.tcp_payload_bytes) > 0 or len(packet.udp_payload_bytes) > 0:
                self.putPacket(packet)

                initialPacket = self.getMatchingPacket(packet)
                if initialPacket != "":
                    classification = self.analyzeFlow(initialPacket, packet)

                    self.handledFlows.add(self.generateKey(initialPacket))

                    key = self.generateKey(initialPacket)

                    # print classification
                    if classification == "Web" or classification == "Unknown":
                        # look for potential video ip, if ip is inside home network switch  to other field...
                        potential_video_ip = pkt['srcip']
                        if self.homePrefix == pkt['srcip']:
                            potential_video_ip = pkt['dstip']

                        # This would be the right way to do it, but googlevideo
                        # does not reverse-dns so we just use the ip-prefixes...
                        # hostname, alias, addresslist = self.lookup(str(potential_video_ip))
                        # # print hostname
                        # if hostname is not None:
                        #     if self.isVideoSite(hostname):
                        #         self.classifiedFlows[key] = "Streaming"
                        #     else:
                        #         self.classifiedFlows[key] = classification
                        # else:
                        #     # fall back to usual web-classification...
                        #     self.classifiedFlows[key] = classification

                        if self.isVideoSiteIp(potential_video_ip):
                            self.classifiedFlows[key] = "Streaming"
                        else:
                            self.classifiedFlows[key] = classification
                    else:
                        self.classifiedFlows[key] = classification

                    # put classified flows on various links:
                    classifier = self.classifiedFlows[key]

                    # self.printClassificationTable()

                    # only do this for high-priority-stuff, the rest has already been taken care of:
                    if classifier == "VOIP" or classifier == "Streaming" or classifier == "Gaming":
                        if classifier == "VOIP":
                            port_up = self.port_up_2
                            port_down = self.port_dn_2
                        elif classifier == "Streaming":
                            port_up = self.port_up_3
                            port_down = self.port_dn_3
                        elif classifier == "Gaming":
                            port_up = self.port_up_4
                            port_down = self.port_dn_4
                        else:
                            port_up = self.port_up_5
                            port_down = self.port_dn_5

                        self.forward = if_(
                            match(switch=self.brup, srcport=pkt['srcport'], dstport=pkt['dstport'], srcip=pkt['srcip'],
                                  dstip=pkt['dstip'], protocol=pkt['protocol'], inport=1), fwd(port_up), self.forward)

                        self.forward = if_(
                            match(switch=self.brup, dstport=pkt['srcport'], srcport=pkt['dstport'], dstip=pkt['srcip'],
                                  srcip=pkt['dstip'], protocol=pkt['protocol'], inport=port_up), fwd(1), self.forward)

                        self.forward = if_(
                            match(switch=self.brdn, dstport=pkt['srcport'], srcport=pkt['dstport'], dstip=pkt['srcip'],
                                  srcip=pkt['dstip'], protocol=pkt['protocol'], inport=1), fwd(port_down), self.forward)

                        self.forward = if_(
                            match(switch=self.brdn, srcport=pkt['srcport'], dstport=pkt['dstport'], srcip=pkt['srcip'],
                                  dstip=pkt['dstip'], protocol=pkt['protocol'], inport=port_down), fwd(1), self.forward)

                        self.update_policy()

    @staticmethod
    def lookup(ip):
        try:
            return socket.gethostbyaddr(str(ip))
        except socket.herror:
            return None, None, None

    @staticmethod
    def ip2int(address):
        out = 0
        for bit in address.to_bits():
            out = (out << 1) | bit
        return out


### Main ###
def main():
    lpi_init_library()
    return flow_classification()