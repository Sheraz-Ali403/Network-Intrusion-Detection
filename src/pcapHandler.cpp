#include <iostream>
#include <stdio.h>
#include <cstdint>  //unit16_t, uint32_t
#include <string>

#include "pcapHandler.h"  

#include "PcapLiveDeviceList.h" //For live capture for v2

//pcap releed header files
#include "PcapFileDevice.h" //For reading pcap files
#include "RawPacket.h" // Packets before parsing
#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

bool PcapHandler::openPcapFile(const std::string& fileName) {
    pcpp::PcapFileReaderDevice reader(fileName);
    if (!reader.open()) {
        std::cerr << "Error opening the pcap file: " << fileName << std::endl;
        return false;
    }
    return true;
}

PacketInfo PcapHandler::getPacketInfo(pcpp::RawPacket& rawPacket) {
    pcpp::Packet packet(&rawPacket);

    auto* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ipv4Layer != nullptr) {
        info.srcIP = ipv4Layer->getSrcIPv4Address().toString();
        info.dstIP = ipv4Layer->getDstIPv4Address().toString();

        //info.protocol = ipv4Layer->getProtocol() == pcpp::TCP ? "TCP" : "UDP";
        //We are limiting to TCP and UDP for now, but we can add more protocols later
        pcpp::ProtocolType protocol = ipv4Layer->getProtocol();
        if(protocol == pcpp::TCP) {
            info.protocol = "TCP";

            auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer != nullptr) {
                info.srcPort = tcpLayer->getTcpHeader()->portSrc;
                info.dstPort = tcpLayer->getTcpHeader()->portDst;
                info.syn = tcpLayer->getTcpHeader()->synFlag;
                info.ack = tcpLayer->getTcpHeader()->ackFlag;
                info.fin = tcpLayer->getTcpHeader()->finFlag;
                info.rst = tcpLayer->getTcpHeader()->rstFlag;
            }
        } 
        else if (protocol == pcpp::UDP) {
            info.protocol = "UDP";

            auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
            if (udpLayer != nullptr) {
                info.srcPort = udpLayer->getUdpHeader()->portSrc;
                info.dstPort = udpLayer->getUdpHeader()->portDst;
            }
        } 
        else {
            info.protocol = "Other";
        }
    }

    

    

    info.packetSize = rawPacket.getRawDataLen();
    // Timestamp handling can be added here

    return info;
}